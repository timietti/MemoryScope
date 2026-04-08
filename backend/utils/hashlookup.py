# backend/utils/hashlookup.py
"""
CIRCL hashlookup pre-filter for IOC enrichment.

Queries https://hashlookup.circl.lu to classify file hashes before they are
sent to VirusTotal, saving both VT API quota and AI prompt tokens.

Each hash in the database carries a `hashlookup:trust` score (0-100):
  >= 50  → known-good  (confirmed legitimate, e.g. from NSRL)
  <  50  → known-malicious (low-trust / threat-intelligence hit)

Hashes absent from the database are returned as unknown and sent to VT
as normal.  Known-good hashes skip VT entirely.  Known-malicious hashes
are still sent to VT for full threat detail (names, detection count, family).

No API key is required.  Results are Redis-cached for 30 days because
file content (and therefore its classification) never changes.
"""
from __future__ import annotations

import hashlib
import json
import logging

import httpx
import redis.asyncio as aioredis

from backend.config import settings

logger = logging.getLogger(__name__)

HL_API_BASE   = "https://hashlookup.circl.lu"
HL_CACHE_TTL  = 86400 * 30   # 30 days
HL_CACHE_PFX  = "hl:cache:"
HL_TIMEOUT    = 30.0
HL_BULK_CHUNK = 100           # CIRCL recommends ≤ 100 per request

# Trust score threshold: >= this value → known-good, < this value → known-malicious
HL_TRUST_THRESHOLD = 50


async def lookup_hashes(hashes: list[dict]) -> dict[str, dict]:
    """
    Query CIRCL hashlookup for a list of hash-type IOCs.

    Args:
        hashes: list of {"type": "md5"|"sha1"|"sha256", "value": str}

    Returns:
        Dict keyed by hash value for hashes **found in the database**.
        Unknown / not-found hashes are absent from the result.
        Each entry contains at least one of:
          {"known_good": True, ...}  — trust >= 50
          {"known_malicious": True, ...}  — trust < 50
    """
    if not hashes:
        return {}

    # Group by hash type, deduplicate
    by_type: dict[str, list[str]] = {}
    for h in hashes:
        t = h["type"]
        if t in ("md5", "sha1", "sha256"):
            by_type.setdefault(t, [])
            if h["value"] not in by_type[t]:
                by_type[t].append(h["value"])

    if not by_type:
        return {}

    results: dict[str, dict] = {}

    async with aioredis.from_url(settings.REDIS_URL) as redis:
        async with httpx.AsyncClient(
            base_url=HL_API_BASE,
            timeout=HL_TIMEOUT,
        ) as client:
            for hash_type, values in by_type.items():
                for i in range(0, len(values), HL_BULK_CHUNK):
                    chunk = values[i : i + HL_BULK_CHUNK]
                    chunk_results = await _lookup_chunk(client, redis, hash_type, chunk)
                    results.update(chunk_results)

    good      = sum(1 for e in results.values() if e.get("known_good"))
    malicious = sum(1 for e in results.values() if e.get("known_malicious"))
    total     = sum(len(v) for v in by_type.values())
    logger.info(
        "Hashlookup: %d/%d hashes found (%d known-good, %d known-malicious)",
        len(results), total, good, malicious,
    )
    return results


async def _lookup_chunk(
    client: httpx.AsyncClient,
    redis: aioredis.Redis,
    hash_type: str,
    values: list[str],
) -> dict[str, dict]:
    """Resolve a single chunk, using Redis cache where available."""
    results: dict[str, dict] = {}
    uncached: list[str] = []

    for value in values:
        cached = await _get_cache(redis, value)
        if cached is not None:
            # Negative cache entries have neither flag set
            if cached.get("known_good") or cached.get("known_malicious"):
                results[value] = cached
        else:
            uncached.append(value)

    if not uncached:
        return results

    try:
        resp = await client.post(
            f"/bulk/{hash_type}",
            json={"hashes": uncached},
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        hits: list[dict] = resp.json()
    except Exception as exc:
        logger.warning("Hashlookup bulk request failed (%s): %s", hash_type, exc)
        return results

    hit_values: set[str] = set()
    for hit in hits:
        value = (
            hit.get("SHA-256")
            or hit.get("SHA-1")
            or hit.get("MD5")
            or ""
        ).lower()
        if not value:
            continue
        hit_values.add(value)
        entry = _normalise_hit(hit)
        results[value] = entry
        await _set_cache(redis, value, entry)

    # Cache negatives so we don't re-query unknown hashes
    for value in uncached:
        if value not in hit_values:
            await _set_cache(redis, value, {})

    return results


def _normalise_hit(hit: dict) -> dict:
    """Classify and extract fields from a CIRCL hashlookup hit."""
    filename = hit.get("FileName") or hit.get("file_name") or ""
    if isinstance(filename, list):
        filename = filename[0] if filename else ""

    trust = hit.get("hashlookup:trust")
    # Entries without a trust score come from NSRL (always legitimate)
    is_malicious = trust is not None and int(trust) < HL_TRUST_THRESHOLD

    return {
        "known_good":      not is_malicious,
        "known_malicious": is_malicious,
        "hl_source":       "CIRCL hashlookup",
        "hl_trust":        trust,
        "hl_filename":     filename,
        "hl_mimetype":     hit.get("mime-type") or hit.get("mimetype") or "",
        "hl_size":         hit.get("FileSize") or hit.get("file_size"),
    }


async def _get_cache(redis: aioredis.Redis, value: str) -> dict | None:
    key = HL_CACHE_PFX + hashlib.sha256(value.encode()).hexdigest()[:16]
    data = await redis.get(key)
    if data:
        return json.loads(data)
    return None


async def _set_cache(redis: aioredis.Redis, value: str, result: dict) -> None:
    key = HL_CACHE_PFX + hashlib.sha256(value.encode()).hexdigest()[:16]
    await redis.setex(key, HL_CACHE_TTL, json.dumps(result))
