# backend/core/strings_extractor.py
"""
Parallel memory-dump strings extraction — streaming design.

Algorithm
---------
1. Split the dump into N equal byte-range chunks (N = min(max_workers, cpu_count),
   capped so each chunk is at most _MAX_CHUNK_BYTES).
2. Each chunk is piped through ``strings -a -el -n8 -td`` in a ThreadPoolExecutor.
   Stdout is read line-by-line; each reported offset is adjusted by the chunk's
   starting file position so the output contains absolute file offsets in the
   format ``"<absolute_offset> <string>"``.  A background thread feeds stdin
   concurrently to avoid pipe-buffer deadlock.
   A 7-byte right-side overlap preserves strings that span chunk boundaries.
3. When all workers finish, ``sort -S256M -u`` merges and deduplicates all temp
   files using disk-based merge sort (≤ 256 MB RAM regardless of input size).
   Boundary strings that appear in two adjacent chunks produce identical
   ``"<same_offset> <string>"`` lines after offset adjustment, so sort -u
   removes the duplicate.
4. Python reads sort's output line-by-line, applies the noise filter to the
   *string part* only, and writes each kept line into the output gzip file —
   never accumulates all output in RAM.

Output format
-------------
Each line in the gzip is ``"<decimal_offset> <string>"``, compatible with the
format expected by Volatility3's ``windows.strings`` plugin (and equivalent to
GNU ``strings -td`` output).

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
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

_MIN_LEN = 8
_MAX_LINE_LEN = 500

# Max bytes fed to a single strings worker. Caps the byte range each worker
# must stream regardless of dump size or worker count.
_MAX_CHUNK_BYTES = 1 * 1024 ** 3   # 1 GB

# Chunk size when streaming dump bytes into strings stdin.
_STDIN_BUF = 4 * 1024 * 1024       # 4 MB

# Applied to the *string part* of each line (not the offset prefix).
_NOISE_RE = re.compile(
    r'^(.)\1{7,}$'      # all-same-char run (8+ repetitions)
    r'|^\s+$'           # whitespace only
    r'|^[0-9]{1,11}$',  # bare integer < 12 digits  (keeps IPs, hashes, etc.)
)


# ── Worker function (runs in a thread pool) ───────────────────────────────────

def _extract_chunk(dump_path: str, file_offset: int, read_size: int, out_path: str) -> str:
    """
    Stream [file_offset, file_offset+read_size) bytes from *dump_path* through
    ``strings -a -el -n8 -td``, adjust each reported (stdin-relative) offset by
    *file_offset* to produce absolute file offsets, and write lines in the form
    ``"<absolute_offset> <string>"`` directly to *out_path*.

    A background thread feeds stdin concurrently so that the main thread can
    drain stdout without risking pipe-buffer deadlock.

    Returns *out_path* so the caller knows which file to merge.
    """
    try:
        proc = subprocess.Popen(
            ["strings", "-a", "-el", f"-n{_MIN_LEN}", "-td"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "'strings' binary not found. Install binutils in the worker image."
        )

    # Feed stdin in a daemon thread to prevent deadlock when the stdout pipe
    # buffer fills up while the parent is blocked writing to stdin.
    def _feed() -> None:
        try:
            with open(dump_path, "rb") as fh:
                fh.seek(file_offset)
                remaining = read_size
                while remaining > 0:
                    piece = fh.read(min(_STDIN_BUF, remaining))
                    if not piece:
                        break
                    proc.stdin.write(piece)  # type: ignore[union-attr]
                    remaining -= len(piece)
        except Exception:
            pass
        finally:
            try:
                proc.stdin.close()  # type: ignore[union-attr]
            except Exception:
                pass

    feeder = threading.Thread(target=_feed, daemon=True)
    feeder.start()

    try:
        with open(out_path, "wb") as out_fh:
            for raw_line in proc.stdout:  # type: ignore[union-attr]
                # GNU strings -td format: right-aligned decimal offset, space, string.
                # e.g. "      0 Hello" or "   1234 cmd.exe"
                line = raw_line.decode("utf-8", errors="replace").rstrip("\n\r")
                parts = line.split(None, 1)  # split on any whitespace, max 1 split
                if len(parts) < 2:
                    continue
                try:
                    rel_offset = int(parts[0])
                except ValueError:
                    continue
                string_part = parts[1]
                abs_offset = file_offset + rel_offset
                out_fh.write(f"{abs_offset} {string_part}\n".encode("utf-8"))
    except Exception:
        proc.kill()
        proc.communicate()
        raise
    finally:
        feeder.join()
        proc.wait(timeout=600)

    return out_path


# ── Public API ────────────────────────────────────────────────────────────────

def extract_strings(dump_path: str, output_path: str, max_workers: int) -> int:
    """
    Run parallel strings extraction on *dump_path*, writing gzip output to
    *output_path*.

    Each line in the output is ``"<decimal_offset> <string>"`` where the offset
    is the absolute byte position of the string within the dump file.  This
    format is directly compatible with Volatility3's ``windows.strings`` plugin.

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
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
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
        # sort -u deduplicates full "offset string" lines. Boundary strings that
        # appear in both adjacent chunks produce the same absolute-offset line
        # after adjustment and are deduplicated here.
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
                    if not line:
                        continue
                    # Lines are "<absolute_offset> <string_part>"
                    # Apply noise filter and length cap to the string part only.
                    space_idx = line.find(" ")
                    if space_idx < 0:
                        continue
                    string_part = line[space_idx + 1:]
                    if (
                        string_part
                        and len(string_part) <= _MAX_LINE_LEN
                        and not _NOISE_RE.match(string_part)
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
