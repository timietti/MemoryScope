# backend/core/strings_extractor.py
"""
Parallel memory-dump strings extraction — streaming design.

Algorithm
---------
1. Split the dump into N equal byte-range chunks (N = min(max_workers, cpu_count),
   capped so each chunk is at most _MAX_CHUNK_BYTES).
2. Each chunk is piped through ``strings -a -el -n8`` in a ProcessPoolExecutor.
   Stdout is written DIRECTLY to a per-chunk temp file — nothing is returned to
   the parent process, so the list-of-strings RAM explosion is avoided.
   A 7-byte right-side overlap preserves strings that span chunk boundaries.
3. When all workers finish, ``sort -S256M -u`` merges and deduplicates all temp
   files using disk-based merge sort (≤ 256 MB RAM regardless of input size).
4. Python reads sort's output line-by-line, applies the noise filter, and writes
   each kept line into the output gzip file — never accumulates all output in RAM.

Peak RAM per worker:  _STDIN_BUF (4 MB) held in Python while streaming to stdin.
Peak RAM for merge:   sort's internal buffer, capped at 256 MB.
No BytesIO accumulation, no large lists returned across process boundaries.
"""
from __future__ import annotations

import gzip
import logging
import os
import re
import subprocess
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed

logger = logging.getLogger(__name__)

_MIN_LEN = 8
_MAX_LINE_LEN = 500

# Max bytes fed to a single strings worker. Caps the byte range each worker
# must stream regardless of dump size or worker count.
_MAX_CHUNK_BYTES = 1 * 1024 ** 3   # 1 GB

# Chunk size when streaming dump bytes into strings stdin.
_STDIN_BUF = 4 * 1024 * 1024       # 4 MB

_NOISE_RE = re.compile(
    r'^(.)\1{7,}$'      # all-same-char run (8+ repetitions)
    r'|^\s+$'           # whitespace only
    r'|^[0-9]{1,11}$',  # bare integer < 12 digits  (keeps IPs, hashes, etc.)
)


# ── Worker function (runs in a subprocess pool) ───────────────────────────────

def _extract_chunk(dump_path: str, offset: int, read_size: int, out_path: str) -> str:
    """
    Stream [offset, offset+read_size) bytes from *dump_path* through
    ``strings -a -el -n8``, writing raw output lines directly to *out_path*.

    stdout goes straight into an open file — nothing is returned across the
    process boundary, so there is no list-of-strings RAM spike in the parent.

    Returns *out_path* so the caller knows which file to merge.
    """
    try:
        with open(out_path, "wb") as out_fh:
            proc = subprocess.Popen(
                ["strings", "-a", "-el", f"-n{_MIN_LEN}"],
                stdin=subprocess.PIPE,
                stdout=out_fh,          # direct file write — no RAM buffer
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
                proc.stdin.write(piece)  # type: ignore[union-attr]
                remaining -= len(piece)
        proc.stdin.close()  # type: ignore[union-attr]
        proc.wait(timeout=600)
    except Exception:
        proc.kill()
        proc.communicate()
        raise

    return out_path


# ── Public API ────────────────────────────────────────────────────────────────

def extract_strings(dump_path: str, output_path: str, max_workers: int) -> int:
    """
    Run parallel strings extraction on *dump_path*, writing gzip output to
    *output_path*.

    Parameters
    ----------
    dump_path:   absolute path to the memory dump file on disk.
    output_path: destination path for the gzip-compressed strings file.
    max_workers: cap on parallel workers (from settings.STRINGS_MAX_WORKERS).

    Returns
    -------
    int — number of lines written after noise filtering.

    Raises
    ------
    RuntimeError  if ``strings`` or ``sort`` binaries are not found.
    """
    dump_size = os.path.getsize(dump_path)
    n_workers = max(1, min(max_workers, os.cpu_count() or 1))

    # Chunk size: at most _MAX_CHUNK_BYTES, split evenly across workers.
    base_chunk = min(_MAX_CHUNK_BYTES, max(dump_size // n_workers, 1))
    overlap = _MIN_LEN - 1

    chunks: list[tuple[int, int]] = []
    offset = 0
    while offset < dump_size:
        size = min(base_chunk, dump_size - offset)
        if offset + size < dump_size:
            size += overlap          # overlap so boundary strings aren't lost
        chunks.append((offset, size))
        offset += base_chunk         # advance without overlap

    logger.info(
        "strings: %d MB dump → %d chunk(s) × ≤%d MB, %d workers",
        dump_size // 1024 ** 2,
        len(chunks),
        base_chunk // 1024 ** 2,
        n_workers,
    )

    # Pre-allocate temp file paths (one per chunk).
    tmp_dir = os.path.dirname(output_path)
    tmp_files: list[str] = []
    for i in range(len(chunks)):
        fd, path = tempfile.mkstemp(prefix=f"str_chunk{i}_", dir=tmp_dir)
        os.close(fd)
        tmp_files.append(path)

    try:
        # ── Phase 1: parallel extraction, each chunk → its own temp file ──────
        with ProcessPoolExecutor(max_workers=n_workers) as pool:
            futures = {
                pool.submit(_extract_chunk, dump_path, off, sz, tmp_files[idx]): idx
                for idx, (off, sz) in enumerate(chunks)
            }
            failed: list[int] = []
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    fut.result()
                    logger.debug("strings: chunk %d done", idx)
                except Exception as exc:
                    logger.warning("strings: chunk %d failed: %s", idx, exc)
                    failed.append(idx)

        # Only merge the temp files that succeeded.
        merge_files = [tmp_files[i] for i in range(len(chunks)) if i not in failed]
        if not merge_files:
            raise RuntimeError("All strings chunks failed — check worker logs.")

        # ── Phase 2: disk-based dedup + noise filter + gzip output ────────────
        try:
            sort_proc = subprocess.Popen(
                ["sort", "-S256M", "-u", *merge_files],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            raise RuntimeError("'sort' binary not found.")

        line_count = 0
        try:
            with gzip.open(output_path, "wb", compresslevel=6) as gz:
                assert sort_proc.stdout is not None
                for raw_line in sort_proc.stdout:
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\n\r")
                    if (
                        line
                        and len(line) <= _MAX_LINE_LEN
                        and not _NOISE_RE.match(line)
                    ):
                        gz.write((line + "\n").encode("utf-8"))
                        line_count += 1
        except Exception:
            sort_proc.kill()
            sort_proc.communicate()
            raise

        sort_proc.wait()

        compressed_kb = os.path.getsize(output_path) // 1024
        logger.info(
            "strings: done — %d lines kept, %d KB compressed", line_count, compressed_kb
        )
        return line_count

    finally:
        # Always clean up chunk temp files.
        for path in tmp_files:
            try:
                os.unlink(path)
            except OSError:
                pass
