# backend/core/strings_extractor.py
"""
Parallel memory-dump strings extraction.

Algorithm
---------
1. Determine worker count: min(STRINGS_MAX_WORKERS, cpu_count).
2. Split the dump into N equal byte-range chunks.
   Each chunk except the last gets a 7-byte right-side overlap so strings
   that span a chunk boundary are not silently dropped (min length is 8).
3. Each chunk is piped through `strings -a -el -n 8` in a
   ProcessPoolExecutor so all workers run concurrently.
4. Output lines are merged into a set (dedup), noise-filtered, sorted,
   then gzip-compressed before being returned as bytes.

Noise filter removes:
  - All-same-character runs  (e.g. "aaaaaaaa")
  - Whitespace-only strings
  - Bare short integers < 12 digits  (longer ones are kept: IPs, hashes)
  - Lines longer than 500 chars       (likely base64 / encoded blobs)
"""
from __future__ import annotations

import gzip
import io
import logging
import os
import re
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed

logger = logging.getLogger(__name__)

_MIN_LEN = 8
_MAX_LINE_LEN = 500

# Compiled once at import time — safe to use from child processes because
# each worker re-imports this module.
_NOISE_RE = re.compile(
    r'^(.)\1{7,}$'      # all-same-char (8+ repetitions)
    r'|^\s+$'           # whitespace only
    r'|^[0-9]{1,11}$',  # bare integer < 12 digits (keeps IPs, MD5s, etc.)
)


# ── Worker function (runs in a subprocess pool) ───────────────────────────────

def _extract_chunk(dump_path: str, offset: int, read_size: int) -> list[str]:
    """
    Read [offset, offset+read_size) bytes from dump_path and pipe through
    `strings -a -el -n 8`.  Returns a list of decoded string lines.

    Runs in a worker process — no shared state with the parent.
    """
    with open(dump_path, "rb") as fh:
        fh.seek(offset)
        data = fh.read(read_size)

    try:
        proc = subprocess.run(
            ["strings", "-a", "-el", f"-n{_MIN_LEN}"],
            input=data,
            capture_output=True,
            timeout=600,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "'strings' binary not found. Install binutils in the worker image."
        )

    return proc.stdout.decode("utf-8", errors="replace").splitlines()


# ── Public API ────────────────────────────────────────────────────────────────

def extract_strings(dump_path: str, max_workers: int) -> tuple[bytes, int]:
    """
    Run parallel strings extraction on *dump_path*.

    Parameters
    ----------
    dump_path:   absolute path to the memory dump file.
    max_workers: cap on parallel workers (from settings.STRINGS_MAX_WORKERS).

    Returns
    -------
    (gzip_compressed_bytes, line_count)
        line_count is the number of unique, noise-filtered lines.
    """
    dump_size = os.path.getsize(dump_path)
    n_workers = max(1, min(max_workers, os.cpu_count() or 1))

    chunk_size = dump_size // n_workers
    # 7-byte overlap at each right-hand boundary so strings that straddle a
    # chunk boundary are captured by the right-side chunk.
    overlap = _MIN_LEN - 1

    chunks: list[tuple[int, int]] = []
    for i in range(n_workers):
        offset = i * chunk_size
        if i < n_workers - 1:
            size = chunk_size + overlap
        else:
            size = dump_size - offset   # last chunk takes the remainder, no overlap
        chunks.append((offset, size))

    logger.info(
        "strings: %d MB dump → %d chunks (max_workers=%d)",
        dump_size // 1024 ** 2,
        n_workers,
        max_workers,
    )

    all_lines: set[str] = set()

    with ProcessPoolExecutor(max_workers=n_workers) as pool:
        futures = {
            pool.submit(_extract_chunk, dump_path, offset, size): idx
            for idx, (offset, size) in enumerate(chunks)
        }
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                lines = fut.result()
                all_lines.update(lines)
                logger.debug("strings: chunk %d → %d lines", idx, len(lines))
            except Exception as exc:
                logger.warning("strings: chunk %d failed: %s", idx, exc)

    # Noise filter + length cap, then sort for stable output
    filtered = sorted(
        line
        for line in all_lines
        if line and len(line) <= _MAX_LINE_LEN and not _NOISE_RE.match(line)
    )

    line_count = len(filtered)
    logger.info("strings: %d unique lines after filter", line_count)

    # Gzip compress (level 6 — good balance of speed vs size for text)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6) as gz:
        for line in filtered:
            gz.write((line + "\n").encode("utf-8", errors="replace"))

    return buf.getvalue(), line_count
