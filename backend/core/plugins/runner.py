# backend/core/plugins/runner.py
"""
Executes Volatility3 plugins as subprocesses in an isolated environment.
Each plugin run is time-limited and output is captured + parsed.
"""
import asyncio
import logging
import os
import shutil
import time
from pathlib import Path
from dataclasses import dataclass

from backend.config import settings
from .registry import PluginSpec

logger = logging.getLogger(__name__)


@dataclass
class PluginResult:
    plugin_name: str
    success: bool
    exit_code: int | None
    raw_output: str
    stderr_output: str
    parsed_output: dict | list | None
    row_count: int
    duration_ms: int
    error_message: str | None = None


async def run_plugin(
    spec: PluginSpec,
    dump_path: str,
    work_dir: Path,
    profile: str | None = None,
) -> PluginResult:
    """
    Run a single Volatility3 plugin against the dump file.

    Args:
        spec:       Plugin specification from the registry
        dump_path:  Path to the memory dump (on local tmpfs)
        work_dir:   Isolated working directory for this analysis run
        profile:    Optional resolved symbol profile/ISF path

    Returns:
        PluginResult with raw and parsed output
    """
    cmd = [
        "python3", settings.VOLATILITY_PATH,
        "--log", str(work_dir / "volatility.log"),
        "-r", "json",
    ]

    # Add symbol server / ISF path if resolved
    if profile:
        cmd += ["--isf-scan", profile]
    if settings.SYMBOL_CACHE_PATH:
        cmd += ["--symbol-dirs", settings.SYMBOL_CACHE_PATH]

    # Memory file
    cmd += ["-f", dump_path]

    # Plugin name and extra args
    cmd += [spec.name] + spec.extra_args

    logger.info("Running plugin %s | cmd: %s", spec.name, " ".join(cmd))

    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(work_dir),
            env=_safe_env(),
            # No network inside worker; enforced by Docker but belt-and-suspenders:
            limit=256 * 1024 * 1024,  # 256MB read buffer
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=settings.PLUGIN_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            elapsed = int((time.monotonic() - start) * 1000)
            return PluginResult(
                plugin_name=spec.name,
                success=False,
                exit_code=None,
                raw_output="",
                stderr_output="",
                parsed_output=None,
                row_count=0,
                duration_ms=elapsed,
                error_message=f"Plugin timed out after {settings.PLUGIN_TIMEOUT_SECONDS}s",
            )

        elapsed = int((time.monotonic() - start) * 1000)
        raw = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        if proc.returncode != 0:
            logger.warning("Plugin %s exited %d | stderr: %s", spec.name, proc.returncode, stderr[:500])
            return PluginResult(
                plugin_name=spec.name,
                success=False,
                exit_code=proc.returncode,
                raw_output=raw,
                stderr_output=stderr,
                parsed_output=None,
                row_count=0,
                duration_ms=elapsed,
                error_message=f"Non-zero exit code: {proc.returncode}",
            )

        # Parse structured output
        parsed, row_count = _parse_output(spec, raw)

        logger.info(
            "Plugin %s complete in %dms | %d rows",
            spec.name, elapsed, row_count
        )
        return PluginResult(
            plugin_name=spec.name,
            success=True,
            exit_code=proc.returncode,
            raw_output=raw,
            stderr_output=stderr,
            parsed_output=parsed,
            row_count=row_count,
            duration_ms=elapsed,
        )

    except Exception as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        logger.exception("Plugin %s failed with exception", spec.name)
        return PluginResult(
            plugin_name=spec.name,
            success=False,
            exit_code=None,
            raw_output="",
            stderr_output="",
            parsed_output=None,
            row_count=0,
            duration_ms=elapsed,
            error_message=str(exc),
        )


def _parse_output(spec: PluginSpec, raw: str) -> tuple[dict | list | None, int]:
    """
    Instantiate the plugin's parser and normalise output.
    Falls back to raw text on parse failure.
    """
    import json
    try:
        # Volatility3 --output json wraps results in {"columns": [...], "rows": [...]}
        data = json.loads(raw)
        parser = spec.parser()
        parsed = parser.parse(data)
        count = len(parsed) if isinstance(parsed, list) else (
            len(parsed.get("rows", [])) if isinstance(parsed, dict) else 0
        )
        return parsed, count
    except Exception as exc:
        logger.warning("Parser %s failed for %s: %s", spec.parser.__name__, spec.name, exc)
        return {"raw_text": raw}, 0


def _safe_env() -> dict:
    """Minimal environment for subprocess — strips credentials from env."""
    safe_keys = {"PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH", "VOLATILITY_SYMBOL_SERVER"}
    return {k: v for k, v in os.environ.items() if k in safe_keys}


async def run_os_detection(dump_path: str, work_dir: Path) -> tuple[str, str | None]:
    """
    Run OS detection plugins and return (os_type, detail_string).
    Tries Windows first, then Linux, then macOS.
    """
    # Step 1: try Windows
    windows_output = await _run_detection_plugin(dump_path, work_dir, "windows.info")
    if windows_output is not None:
        return "windows", _extract_os_detail(windows_output, "windows")

    # Step 2: try banners (covers both Linux and macOS)
    banners_output = await _run_detection_plugin(dump_path, work_dir, "banners")
    if banners_output is not None:
        if "Linux" in banners_output:
            return "linux", _extract_os_detail(banners_output, "linux")
        if "Darwin" in banners_output:
            return "macos", _extract_os_detail(banners_output, "macos")
        logger.warning("banners plugin ran but output contains neither 'Linux' nor 'Darwin'")

    return "unknown", None


async def _run_detection_plugin(dump_path: str, work_dir: Path, plugin_name: str) -> str | None:
    """
    Run a single Volatility3 plugin for OS detection.
    Returns stdout string on success (exit 0, non-empty output), or None on failure/timeout.
    """
    cmd = [
        "python3", settings.VOLATILITY_PATH,
        "-r", "json",
        "-f", dump_path,
        plugin_name,
    ]
    logger.info("OS detection cmd: %s", " ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(work_dir),
            env=_safe_env(),
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning("OS detection timed out for %s", plugin_name)
            return None

        stdout_str = stdout.decode("utf-8", errors="replace")
        stderr_str = stderr.decode("utf-8", errors="replace")
        logger.info("OS detection %s: exit=%s stdout_len=%d stderr=%s",
                    plugin_name, proc.returncode, len(stdout_str), stderr_str[:300] or "(empty)")

        if proc.returncode == 0 and stdout_str.strip():
            return stdout_str
        return None
    except Exception as exc:
        logger.warning("OS detection exception for %s: %s", plugin_name, exc)
        return None


def _extract_os_detail(raw: str, os_type: str) -> str | None:
    import json
    try:
        data = json.loads(raw)
        rows = data if isinstance(data, list) else data.get("rows", [])
        rows = [r for r in rows if isinstance(r, dict) and not r.get("__isMetadata")]
        if not rows:
            return None
        row = rows[0]
        # For banners output prefer the human-readable Banner string over the full dict repr
        if "Banner" in row:
            detail = str(row["Banner"])
        else:
            # windows.info: use NtBuildLab or fall back to full row
            detail = str(row.get("NtBuildLab") or row.get("NtMajorVersion") or row)
        return detail[:255]
    except Exception:
        pass
    return None


def prepare_work_dir(case_id: str) -> Path:
    """Create a fresh isolated working directory for this analysis run."""
    work_dir = Path(settings.WORKER_TMP_DIR) / case_id
    work_dir.mkdir(parents=True, exist_ok=True)
    return work_dir


def cleanup_work_dir(work_dir: Path) -> None:
    """Securely remove the working directory after analysis."""
    try:
        shutil.rmtree(work_dir, ignore_errors=False)
        logger.info("Cleaned up work dir: %s", work_dir)
    except Exception as exc:
        logger.error("Failed to clean up work dir %s: %s", work_dir, exc)
