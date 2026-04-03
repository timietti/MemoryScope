# backend/utils/enrichment.py
"""
VirusTotal IOC enrichment.
Requests are sent concurrently (semaphore-bounded) rather than serially.
VT_RATE_LIMIT_PER_MIN controls the configured quota (default 4 free / 500 premium).
Results are cached in Redis to avoid duplicate lookups across cases.
"""
from __future__ import annotations
import asyncio
import hashlib
import json
import logging
from typing import Any

import httpx
import redis.asyncio as aioredis

from backend.config import settings

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"
CACHE_TTL_SECONDS = 86400 * 7   # Cache results for 7 days


async def enrich_iocs(iocs: list[dict]) -> dict[str, Any]:
    """
    Enrich a list of IOCs with VirusTotal data.
    
    Args:
        iocs: List of {"type": "ip"|"md5"|"sha256"|etc., "value": str}
    
    Returns:
        Dict keyed by IOC value with VT result data.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        logger.info("VT API key not set; skipping enrichment")
        return {}

    api_key = settings.VIRUSTOTAL_API_KEY.get_secret_value()
    results = {}

    # Deduplicate, then cap at VT_MAX_IOCS to avoid rate-limit timeouts.
    # Hashes are prioritised over IPs (more actionable for triage).
    unique_all = {i["value"]: i["type"] for i in iocs}
    hashes = {v: t for v, t in unique_all.items() if t in ("md5", "sha1", "sha256")}
    ips    = {v: t for v, t in unique_all.items() if t == "ip"}
    cap = settings.VT_MAX_IOCS
    unique = dict(list(hashes.items())[:cap])
    remaining = cap - len(unique)
    if remaining > 0:
        unique.update(dict(list(ips.items())[:remaining]))
    if len(unique_all) > cap:
        logger.info("VT cap: submitting %d/%d IOCs (hashes first)", len(unique), len(unique_all))

    # Concurrency limit: cap in-flight requests to avoid overwhelming VT.
    # At 500/min the bottleneck is network RTT not the quota, so a small
    # concurrency window (20) keeps throughput high without hammering the API.
    semaphore = asyncio.Semaphore(20)

    async with aioredis.from_url(settings.REDIS_URL) as redis:
        async with httpx.AsyncClient(
            base_url=VT_API_BASE,
            headers={"x-apikey": api_key},
            timeout=30.0,
        ) as client:
            async def _enrich_one(value: str, ioc_type: str) -> tuple[str, dict | None]:
                try:
                    cached = await _get_cache(redis, value)
                    if cached:
                        return value, cached
                    async with semaphore:
                        result = await _lookup_vt(client, value, ioc_type)
                    if result:
                        await _set_cache(redis, value, result)
                    return value, result
                except Exception as exc:
                    logger.warning("VT lookup failed for %s: %s", value, exc)
                    return value, None

            pairs = await asyncio.gather(*[_enrich_one(v, t) for v, t in unique.items()])
            results = {v: r for v, r in pairs if r is not None}

    logger.info("VT enrichment complete: %d/%d IOCs enriched", len(results), len(unique))
    return results


async def _lookup_vt(client: httpx.AsyncClient, value: str, ioc_type: str) -> dict | None:
    """Make a single VT API request and normalise the response."""
    
    # Map our IOC type to VT API endpoint
    endpoint_map = {
        "ip": f"/ip_addresses/{value}",
        "domain": f"/domains/{value}",
        "url": f"/urls/{_url_id(value)}",
        "md5": f"/files/{value}",
        "sha1": f"/files/{value}",
        "sha256": f"/files/{value}",
    }
    
    endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        return None

    try:
        resp = await client.get(endpoint)
        if resp.status_code == 404:
            return {"status": "not_found", "positives": 0, "total": 0}
        if resp.status_code == 429:
            logger.warning("VT rate limit hit; backing off 60s")
            await asyncio.sleep(60)
            resp = await client.get(endpoint)
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.warning("VT HTTP error for %s: %s", value, exc)
        return None

    data = resp.json().get("data", {})
    attrs = data.get("attributes", {})
    
    # Normalise: different VT response schemas for IPs, files, domains
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    
    # Extract threat names from results
    results = attrs.get("last_analysis_results", {})
    threat_names = list({
        r.get("result") for r in results.values()
        if r.get("category") == "malicious" and r.get("result")
    })[:5]

    return {
        "positives": malicious,
        "total": total,
        "permalink": f"https://www.virustotal.com/gui/{_vt_type(ioc_type)}/{value}",
        "threat_names": threat_names,
        "reputation": attrs.get("reputation", 0),
        "country": attrs.get("country"),           # for IPs
        "tags": attrs.get("tags", []),
    }


def _url_id(url: str) -> str:
    """VT URL endpoint requires base64url-encoded URL."""
    import base64
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


def _vt_type(ioc_type: str) -> str:
    return {
        "ip": "ip-address", "domain": "domain",
        "url": "url", "md5": "file", "sha1": "file", "sha256": "file",
    }.get(ioc_type, "search")


async def _get_cache(redis: aioredis.Redis, value: str) -> dict | None:
    key = f"vt:cache:{hashlib.sha256(value.encode()).hexdigest()[:16]}"
    data = await redis.get(key)
    if data:
        return json.loads(data)
    return None


async def _set_cache(redis: aioredis.Redis, value: str, result: dict) -> None:
    key = f"vt:cache:{hashlib.sha256(value.encode()).hexdigest()[:16]}"
    await redis.setex(key, CACHE_TTL_SECONDS, json.dumps(result))
