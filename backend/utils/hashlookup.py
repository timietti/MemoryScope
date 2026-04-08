# backend/utils/hashlookup.py
"""
CIRCL hashlookup pre-filter for IOC enrichment.

Queries https://hashlookup.circl.lu to identify known-good file hashes
before they are sent to VirusTotal. Hashes confirmed as known-good are
returned with file metadata so they can be annotated in the DB and skipped
in the VT queue — saving both VT API quota and tokens in the AI prompt.

No API key is required. Results are Redis-cached for 30 days because
known-good status is highly stable (file content doesn't change).
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
HL_CACHE_TTL  = 86400 * 30   # 30 days — known-good is stable
HL_CACHE_PFX  = "hl:cache:"
HL_TIMEOUT    = 30.0
# Max hashes per bulk request (CIRCL recommends ≤ 100)
HL_BULK_CHUNK = 100


async def lookup_known_good(hashes: list[dict]) -> dict[str, dict]:
    """
    Query CIRCL hashlookup for a list of hash-type IOCs.

    Args:
        hashes: list of {"type": "md5"|"sha1"|"sha256", "value": str}

    Returns:
        Dict keyed by hash value for **confirmed known-good** hashes only.
        Unknown / not-found hashes are absent from the result.
        Each value is a dict with at least {"known_good": True}.
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
                # Split into chunks to stay within CIRCL's recommended limit
                for i in range(0, len(values), HL_BULK_CHUNK):
                    chunk = values[i : i + HL_BULK_CHUNK]
                    chunk_results = await _lookup_chunk(client, redis, hash_type, chunk)
                    results.update(chunk_results)

    logger.info(
        "Hashlookup: %d/%d hashes confirmed known-good",
        len(results),
        sum(len(v) for v in by_type.values()),
    )
    return results


async def _lookup_chunk(
    client: httpx.AsyncClient,
    redis: aioredis.Redis,
    hash_type: str,
    values: list[str],
) -> dict[str, dict]:
    """Resolve a single chunk of hashes, using Redis cache where available."""
    results: dict[str, dict] = {}
    uncached: list[str] = []

    # Check cache first
    for value in values:
        cached = await _get_cache(redis, value)
        if cached is not None:
            if cached.get("known_good"):
                results[value] = cached
        else:
            uncached.append(value)

    if not uncached:
        return results

    # Bulk lookup for cache misses
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

    # CIRCL bulk response is a list of hit objects; hashes NOT in the list are unknown
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

    # Cache negative results so we don't re-query them
    for value in uncached:
        if value not in hit_values:
            await _set_cache(redis, value, {"known_good": False})

    return results


def _normalise_hit(hit: dict) -> dict:
    """Extract the most useful fields from a CIRCL hashlookup hit."""
    filename = hit.get("FileName") or hit.get("file_name") or ""
    # FileName may be a list or a string
    if isinstance(filename, list):
        filename = filename[0] if filename else ""

    return {
        "known_good": True,
        "hl_source":   "CIRCL hashlookup",
        "hl_filename": filename,
        "hl_mimetype": hit.get("mime-type") or hit.get("mimetype") or "",
        "hl_size":     hit.get("FileSize") or hit.get("file_size"),
        "hl_tags":     hit.get("KnownMalicious", []) or [],   # usually empty for known-good
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
