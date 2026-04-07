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

# Maximum bytes fed to a single strings worker process.
# Caps peak RAM per worker at ~1 GB regardless of dump size or worker count.
# Larger dumps are split into more chunks; extras are queued behind the workers.
_MAX_CHUNK_BYTES = 1 * 1024 ** 3   # 1 GB

# Chunk size when streaming dump bytes into strings stdin.
# Never more than this many bytes in Python memory at one time per worker.
_STDIN_BUF = 4 * 1024 * 1024       # 4 MB

_NOISE_RE = re.compile(
    r'^(.)\1{7,}$'      # all-same-char (8+ repetitions)
    r'|^\s+$'           # whitespace only
    r'|^[0-9]{1,11}$',  # bare integer < 12 digits (keeps IPs, MD5s, etc.)
)


# ── Worker function (runs in a subprocess pool) ───────────────────────────────

def _extract_chunk(dump_path: str, offset: int, read_size: int) -> list[str]:
    """
    Pipe [offset, offset+read_size) bytes from dump_path through
    `strings -a -el -n 8` using streaming stdin — at most _STDIN_BUF bytes
    of the dump are held in Python memory at any one time.

    Runs in a worker process — no shared state with the parent.
    """
    try:
        proc = subprocess.Popen(
            ["strings", "-a", "-el", f"-n{_MIN_LEN}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "'strings' binary not found. Install binutils in the worker image."
        )

    try:
        with open(dump_path, "rb") as fh:
            fh.seek(offset)
            remaining = read_size
            while remaining > 0:
                piece = fh.read(min(_STDIN_BUF, remaining))
                if not piece:
                    break
                proc.stdin.write(piece)
                remaining -= len(piece)
        proc.stdin.close()
        stdout, _ = proc.communicate(timeout=600)
    except Exception:
        proc.kill()
        proc.communicate()
        raise

    return stdout.decode("utf-8", errors="replace").splitlines()


# ── Public API ────────────────────────────────────────────────────────────────

def extract_strings(dump_path: str, max_workers: int) -> tuple[bytes, int]:
    """
    Run parallel strings extraction on *dump_path*.

    The dump is split into chunks of at most _MAX_CHUNK_BYTES (1 GB) each,
    capping peak RAM per worker regardless of dump size.  Up to max_workers
    chunks are processed concurrently; any extras are queued.

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

    # Split into chunks no larger than _MAX_CHUNK_BYTES.
    # If the dump is small, we may get fewer chunks than n_workers — that's fine.
    base_chunk = min(_MAX_CHUNK_BYTES, max(dump_size // n_workers, 1))
    overlap = _MIN_LEN - 1

    chunks: list[tuple[int, int]] = []
    offset = 0
    while offset < dump_size:
        size = min(base_chunk, dump_size - offset)
        # Add overlap (except on the last chunk) so strings spanning a boundary
        # are captured by the right-side chunk.
        if offset + size < dump_size:
            size += overlap
        chunks.append((offset, size))
        offset += base_chunk   # advance by base_chunk, not size+overlap

    logger.info(
        "strings: %d MB dump → %d chunk(s), %d MB each, max_workers=%d",
        dump_size // 1024 ** 2,
        len(chunks),
        base_chunk // 1024 ** 2,
        n_workers,
    )

    all_lines: set[str] = set()

    with ProcessPoolExecutor(max_workers=n_workers) as pool:
        futures = {
            pool.submit(_extract_chunk, dump_path, off, sz): idx
            for idx, (off, sz) in enumerate(chunks)
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

    # Gzip compress
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6) as gz:
        for line in filtered:
            gz.write((line + "\n").encode("utf-8", errors="replace"))

    return buf.getvalue(), line_count
