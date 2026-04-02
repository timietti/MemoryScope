# backend/core/symbols/linux_builder.py
"""
Linux symbol table builder for Volatility3.

Supports Ubuntu, Debian, Fedora, and RHEL-family (CentOS/Rocky/AlmaLinux/RHEL)
kernels, plus a universal debuginfod fallback for any distro.

Given a kernel banner string (from the `banners` plugin), this module:
  1. Parses the kernel version and architecture.
  2. Locates the matching debug package (Launchpad for Ubuntu,
     snapshot.debian.org for Debian, Koji XML-RPC for Fedora,
     HTTP-browsable dirs for RHEL-family).
  3. Downloads and extracts the package to get the vmlinux ELF.
  4. Runs `dwarf2json linux --elf <vmlinux> | xz` to generate the ISF file.
  5. Places the ISF at `{SYMBOL_CACHE_PATH}/linux/<version_short>.json.xz`.

The debuginfod fallback (`build_symbols_via_debuginfod`) extracts the kernel's
GNU build-ID from the dump and fetches the debuginfo ELF directly from public
debuginfod servers, bypassing the need to download a full debug package.

The result is a ready-to-use Volatility3 symbol table for that exact kernel.
"""
from __future__ import annotations

import logging
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import NamedTuple

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)

# ── Banner regexes ────────────────────────────────────────────────────────────

# Ubuntu: Linux version 5.15.0-91-generic (...) (Ubuntu 5.15.0-91.101~20.04.1 ...) ...
# Groups:
#   1 - version_short   e.g. "5.15.0-91-generic"
#   2 - version_ubuntu  e.g. "5.15.0-91.101"
_BANNER_RE = re.compile(
    r"Linux version (\d+\.\d+\.\d+-\d+-\S+)"        # version_short (kernel ABI string)
    r".+?\(Ubuntu\s+(\d+\.\d+\.\d+-\d+\.\d+)"        # version_ubuntu (package version prefix)
)

# Debian: Linux version 6.1.0-18-amd64 (...) #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)
# The date suffix "(YYYY-MM-DD)" distinguishes the build-info Debian token from
# the compiler version "(Debian 12.2.0-14)" that also appears in the banner.
# Groups:
#   1 - version_short    e.g. "6.1.0-18-amd64"
#   2 - package_version  e.g. "6.1.76-1"
_DEBIAN_BANNER_RE = re.compile(
    r"Linux version (\d+\.\d+\.\d+-\d+-\S+)"            # version_short
    r".*?Debian\s+([\d][\d.+~]*)\s+\(\d{4}-\d{2}-\d{2}\)"  # package_version + date
)

# snapshot.debian.org base URL
_SNAPSHOT_API = "https://snapshot.debian.org/mr"
_SNAPSHOT_FILE = "https://snapshot.debian.org/file"

# Fedora: Linux version 6.5.6-300.fc39.x86_64 (mockbuild@...) ...
# Detected by the .fcNN. component in the version string.
# Groups:
#   1 - version_short    e.g. "6.5.6-300.fc39.x86_64"  (full kernel ABI)
#   2 - version_noarch   e.g. "6.5.6-300.fc39"          (used as Koji NVR suffix)
_FEDORA_BANNER_RE = re.compile(
    r"Linux version ((\d+\.\d+\.\d+-\d+\.fc\d+)\.\S+)"  # 1=full, 2=no-arch
)

# Koji XML-RPC hub and package download base
_KOJI_HUB = "https://koji.fedoraproject.org/kojihub"
_KOJI_PKGS = "https://kojipkgs.fedoraproject.org/packages"

# RHEL-family: Linux version 4.18.0-477.10.1.el8_8.x86_64 (mockbuild@...) ...
# Detected by .elN[_.] in the kernel version string.
# Groups:
#   1 - version_short   e.g. "4.18.0-477.10.1.el8_8.x86_64"
#   2 - version_noarch  e.g. "4.18.0-477.10.1.el8_8"   (NVR minus arch)
#   3 - el_tag          e.g. "el8"                       (major version)
_RHEL_BANNER_RE = re.compile(
    r"Linux version ((\d+\.\d+\.\d+-[\d.]+\.(el\d+)[_.\S]*?)\.(x86_64|aarch64|s390x))\s"
)

# Per-distro debuginfo base URLs.  {major} = "8" or "9", {arch} = "x86_64" etc.
# Each entry is tried in order; the first 200 response wins.
_RHEL_DEBUGINFO_URLS: dict[str, list[str]] = {
    # CentOS Stream — flat debuginfo tree
    "centos": [
        "https://debuginfo.centos.org/{major}-stream/{arch}/"
        "kernel-debuginfo-{ver}-{rel}.{arch}.rpm",
        "https://debuginfo.centos.org/{major}/{arch}/"
        "kernel-debuginfo-{ver}-{rel}.{arch}.rpm",
    ],
    # Rocky Linux — Packages/k/ sub-directory
    "rocky": [
        "https://download.rockylinux.org/pub/rocky/{major}/BaseOS/{arch}/debug/tree/Packages/k/"
        "kernel-debuginfo-{ver}-{rel}.{arch}.rpm",
    ],
    # AlmaLinux — same layout as Rocky
    "alma": [
        "https://repo.almalinux.org/almalinux/{major}/BaseOS/{arch}/debug/Packages/k/"
        "kernel-debuginfo-{ver}-{rel}.{arch}.rpm",
        "https://repo.almalinux.org/vault/{major}/BaseOS/{arch}/debug/Packages/k/"
        "kernel-debuginfo-{ver}-{rel}.{arch}.rpm",
    ],
}

# Generic Linux version extractor — used when no distro parser matched
_LINUX_VERSION_RE = re.compile(r"Linux version (\S+)")

# Debuginfod public servers, tried in order
_DEBUGINFOD_SERVERS = [
    "https://debuginfod.elfutils.org",       # aggregator — covers many distros
    "https://debuginfod.fedoraproject.org",
    "https://debuginfod.debian.net",
    "https://debuginfod.ubuntu.com",
]

# GNU build-ID ELF note signature:
#   type field (uint32 LE) = 3 (NT_GNU_BUILD_ID)  followed by  name = "GNU\0"
# Searching for this 8-byte sequence and reading descsz from 4 bytes before it
# correctly locates the build-ID in both ELF vmcore and raw/LiME dumps.
_NOTE_TYPE_NAME = b"\x03\x00\x00\x00GNU\x00"
_DEBUGINFOD_SCAN_BYTES = 64 * 1024 * 1024   # scan first 64 MB of dump

# Launchpad API base
_LP_API = "https://api.launchpad.net/devel"
_LP_WEB = "https://launchpad.net"
_LP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}
_LAUNCHPAD_LIB = re.compile(
    r'href="(https?://launchpadlibrarian\.net/\S+\.ddeb)"'
)


class KernelInfo(NamedTuple):
    version_short: str    # e.g. "5.15.0-91-generic"
    version_extended: str # e.g. "5.15.0-91.101" (from Ubuntu build)
    arch: str             # e.g. "amd64"


def parse_ubuntu_banner(banner: str) -> KernelInfo | None:
    """
    Extract kernel version info from a Volatility3 banner string.
    Returns None if the banner is not a recognised Ubuntu kernel.
    """
    m = _BANNER_RE.search(banner)
    if not m:
        logger.debug("Banner does not match Ubuntu pattern: %r", banner[:120])
        return None

    version_short = m.group(1)   # e.g. "5.15.0-91-generic"
    version_ubuntu = m.group(2)  # e.g. "5.15.0-91.101"

    # Determine arch from banner keyword (SMP PREEMPT x86_64 / aarch64)
    if "aarch64" in banner or "arm64" in banner:
        arch = "arm64"
    else:
        arch = "amd64"

    # Build the extended version string as Launchpad knows it:
    # e.g. "5.15.0-91.101" → the package version field without extra Ubuntu suffix
    return KernelInfo(
        version_short=version_short,
        version_extended=version_ubuntu,
        arch=arch,
    )


def parse_debian_banner(banner: str) -> KernelInfo | None:
    """
    Extract kernel version info from a Debian kernel banner string.
    Returns None if the banner is not a recognised Debian kernel.

    Example banner:
      Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org)
      (gcc-12 (Debian 12.2.0-14) 12.2.0, ...) #1 SMP PREEMPT_DYNAMIC
      Debian 6.1.76-1 (2024-02-01)
    """
    m = _DEBIAN_BANNER_RE.search(banner)
    if not m:
        logger.debug("Banner does not match Debian pattern: %r", banner[:120])
        return None

    version_short = m.group(1)    # e.g. "6.1.0-18-amd64"
    package_version = m.group(2)  # e.g. "6.1.76-1"

    if "aarch64" in banner or "arm64" in banner:
        arch = "arm64"
    else:
        arch = "amd64"

    return KernelInfo(
        version_short=version_short,
        version_extended=package_version,
        arch=arch,
    )


def parse_fedora_banner(banner: str) -> KernelInfo | None:
    """
    Extract kernel version info from a Fedora kernel banner string.
    Returns None if the banner is not a recognised Fedora kernel.

    Example banner:
      Linux version 6.5.6-300.fc39.x86_64 (mockbuild@...) (gcc ...) #1 SMP ...
    """
    m = _FEDORA_BANNER_RE.search(banner)
    if not m:
        logger.debug("Banner does not match Fedora pattern: %r", banner[:120])
        return None

    version_short = m.group(1)   # e.g. "6.5.6-300.fc39.x86_64"
    version_noarch = m.group(2)  # e.g. "6.5.6-300.fc39"

    if "aarch64" in banner:
        arch = "aarch64"
    else:
        arch = "x86_64"

    return KernelInfo(
        version_short=version_short,
        version_extended=version_noarch,
        arch=arch,
    )


def parse_rhel_banner(banner: str) -> KernelInfo | None:
    """
    Extract kernel version info from a RHEL-family banner string.
    Returns None if the banner is not a recognised RHEL/CentOS/Rocky/AlmaLinux kernel.

    Example banners:
      Linux version 4.18.0-477.10.1.el8_8.x86_64 (mockbuild@...) ... CentOS ...
      Linux version 5.14.0-284.11.1.el9_2.x86_64 (mockbuild@...) ... Red Hat ...
    """
    m = _RHEL_BANNER_RE.search(banner)
    if not m:
        logger.debug("Banner does not match RHEL pattern: %r", banner[:120])
        return None

    version_short  = m.group(1)   # e.g. "4.18.0-477.10.1.el8_8.x86_64"
    version_noarch = m.group(2)   # e.g. "4.18.0-477.10.1.el8_8"
    arch           = m.group(4)   # e.g. "x86_64"

    return KernelInfo(
        version_short=version_short,
        version_extended=version_noarch,
        arch=arch,
    )


# ── Launchpad helpers ─────────────────────────────────────────────────────────

def _get_ubuntu_releases() -> list[str]:
    """Return list of Ubuntu release series names (e.g. ['noble', 'jammy', ...])."""
    try:
        resp = httpx.get(
            f"{_LP_API}/ubuntu/series",
            headers={**_LP_HEADERS, "Accept": "application/json"},
            timeout=15,
            follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()
        # Most recent first, filter only active/current/supported series
        entries = data.get("entries", [])
        series = [
            e["name"] for e in entries
            if e.get("status") in ("Active Development", "Current Stable Release",
                                   "Supported", "LTS Supported")
        ]
        logger.debug("Ubuntu series from Launchpad: %s", series)
        return series
    except Exception:
        logger.warning("Could not fetch Ubuntu series from Launchpad, using defaults")
        return ["jammy", "focal", "bionic", "noble", "xenial"]


def _find_ddeb_url(info: KernelInfo, series: list[str]) -> str | None:
    """
    Try to find the .ddeb download URL for the given kernel on Launchpad.
    Tries both unsigned and plain linux-image package names across all series.
    """
    pkg_patterns = [
        f"linux-image-unsigned-{info.version_short}-dbgsym",
        f"linux-image-{info.version_short}-dbgsym",
    ]
    for release in series:
        for pkg in pkg_patterns:
            url = (
                f"{_LP_WEB}/ubuntu/{release}/{info.arch}"
                f"/{pkg}/{info.version_extended}"
            )
            for attempt in range(3):
                try:
                    if attempt > 0:
                        time.sleep(5 * attempt)
                    resp = httpx.get(url, headers=_LP_HEADERS, timeout=30, follow_redirects=True)
                    if resp.status_code != 200:
                        logger.debug("Launchpad %s → %d", url, resp.status_code)
                        break  # no point retrying a 404
                    m = _LAUNCHPAD_LIB.search(resp.text)
                    if m:
                        ddeb_url = m.group(1)
                        logger.info(
                            "Found ddeb for %s/%s at %s (series=%s)",
                            info.version_short, info.version_extended, ddeb_url, release,
                        )
                        return ddeb_url
                    break
                except httpx.HTTPError as exc:
                    logger.warning("Request failed for %s (attempt %d): %s", url, attempt + 1, exc)
            time.sleep(1)  # brief pause between each URL to avoid rate limiting
    return None


def _download_file(url: str, dest: Path, max_retries: int = 5) -> None:
    """Streaming download to dest path with resume support and retries."""
    logger.info("Downloading %s → %s", url, dest)
    for attempt in range(max_retries):
        existing = dest.stat().st_size if dest.exists() else 0
        headers = {**_LP_HEADERS}
        if existing:
            headers["Range"] = f"bytes={existing}-"
            logger.info("Resuming download from byte %d (attempt %d)", existing, attempt + 1)
        try:
            with httpx.stream("GET", url, headers=headers, timeout=120, follow_redirects=True) as resp:
                if resp.status_code == 416:
                    # Range not satisfiable — file already complete
                    break
                resp.raise_for_status()
                mode = "ab" if resp.status_code == 206 else "wb"
                if mode == "wb" and existing:
                    logger.info("Server does not support resume — restarting download")
                with dest.open(mode) as fh:
                    for chunk in resp.iter_bytes(chunk_size=1024 * 1024):
                        fh.write(chunk)
            break  # success
        except httpx.HTTPError as exc:
            if attempt == max_retries - 1:
                raise
            wait = 5 * (attempt + 1)
            logger.warning("Download error (attempt %d/%d): %s — retrying in %ds",
                           attempt + 1, max_retries, exc, wait)
            time.sleep(wait)
    logger.info("Downloaded %s (%.1f MB)", dest.name, dest.stat().st_size / 1024 / 1024)


def _extract_vmlinux(ddeb_path: Path, extract_dir: Path) -> Path | None:
    """
    Extract the ddeb archive and find the vmlinux ELF debug symbol file.
    Returns the path to vmlinux, or None if not found.
    """
    subprocess.run(
        ["dpkg-deb", "-x", str(ddeb_path), str(extract_dir)],
        check=True, timeout=120,
        capture_output=True,
    )
    # The file is typically at usr/lib/debug/boot/vmlinux-<version>
    candidates = list(extract_dir.rglob("vmlinux*"))
    if not candidates:
        logger.error("No vmlinux file found inside ddeb at %s", ddeb_path)
        return None
    # Prefer the largest file (the full ELF)
    vmlinux = max(candidates, key=lambda p: p.stat().st_size)
    logger.info("Using vmlinux: %s (%.1f MB)", vmlinux, vmlinux.stat().st_size / 1024 / 1024)
    return vmlinux


def _patch_linux_banner(isf_path: Path, banner: str) -> None:
    """
    Patch the linux_banner.constant_data field in a generated ISF (.json.xz).

    dwarf2json leaves this field with the wrong value (contains trailing \\n\\x00
    from the vmlinux ELF string table).  Volatility3 uses it to verify the symbol
    table matches the dump, so it must be the base64 encoding of the plain banner
    string exactly as extracted from the dump — no trailing bytes.

    Raises RuntimeError if the linux_banner symbol is absent from the ISF (fatal).
    """
    import base64
    import json
    import lzma

    logger.info("Patching linux_banner.constant_data in %s", isf_path)

    compressed = isf_path.read_bytes()
    data = json.loads(lzma.decompress(compressed))

    if "linux_banner" not in data.get("symbols", {}):
        raise RuntimeError(
            f"linux_banner symbol not found in ISF {isf_path} — "
            "the symbol table cannot be used by Volatility3"
        )

    correct_value = base64.b64encode(banner.encode("utf-8")).decode("ascii")
    data["symbols"]["linux_banner"]["constant_data"] = correct_value

    patched = lzma.compress(json.dumps(data).encode("utf-8"))

    # Atomic replace
    tmp_path = isf_path.with_suffix(".tmp")
    try:
        tmp_path.write_bytes(patched)
        tmp_path.rename(isf_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    logger.info("Patched linux_banner.constant_data in %s", isf_path)


def _run_dwarf2json(vmlinux: Path, output_path: Path) -> None:
    """
    Run `dwarf2json linux --elf <vmlinux>` and compress output with xz.
    Writes the resulting JSON.xz to output_path.
    """
    dwarf2json = settings.DWARF2JSON_PATH
    logger.info("Running dwarf2json on %s → %s", vmlinux, output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Pipeline: dwarf2json | xz > output_path
    with output_path.open("wb") as out_fh:
        dw_proc = subprocess.Popen(
            [dwarf2json, "linux", "--elf", str(vmlinux)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        xz_proc = subprocess.Popen(
            ["xz", "-T0", "-"],
            stdin=dw_proc.stdout,
            stdout=out_fh,
            stderr=subprocess.PIPE,
        )
        dw_proc.stdout.close()  # allow dw_proc to receive SIGPIPE if xz_proc exits

        xz_proc.wait()
        dw_proc.wait()

    if dw_proc.returncode != 0:
        stderr = dw_proc.stderr.read().decode(errors="replace")
        raise RuntimeError(f"dwarf2json failed (rc={dw_proc.returncode}): {stderr[:500]}")
    if xz_proc.returncode != 0:
        raise RuntimeError(f"xz compression failed (rc={xz_proc.returncode})")

    size_mb = output_path.stat().st_size / 1024 / 1024
    logger.info("Symbol table written: %s (%.1f MB)", output_path, size_mb)


# ── Fedora / Koji helpers ────────────────────────────────────────────────────


def _find_rpm_url_fedora(info: KernelInfo) -> str | None:
    """
    Locate the kernel-debuginfo RPM for the given Fedora kernel via the Koji
    XML-RPC API.

    info.version_extended is expected to be "X.Y.Z-NNN.fcNN" (no arch suffix).
    Returns a direct kojipkgs.fedoraproject.org download URL, or None.
    """
    import xmlrpc.client

    # Split "6.5.6-300.fc39" → version="6.5.6", release="300.fc39"
    try:
        kver, krel = info.version_extended.rsplit("-", 1)
    except ValueError:
        logger.warning("Cannot parse Fedora version_extended %r", info.version_extended)
        return None

    nvr = f"kernel-{kver}-{krel}"
    logger.info("Looking up Fedora kernel build in Koji: %s", nvr)

    try:
        hub = xmlrpc.client.ServerProxy(_KOJI_HUB, allow_none=True)
        build = hub.getBuild(nvr)
        if not build:
            logger.warning("Koji: no build found for NVR %s", nvr)
            return None

        build_id = build["id"]
        rpms = hub.listRPMs(buildID=build_id)
    except Exception as exc:
        logger.warning("Koji XML-RPC call failed for %s: %s", nvr, exc)
        return None

    # Find kernel-debuginfo for our arch
    target_rpm = next(
        (r for r in rpms
         if r.get("name") == "kernel-debuginfo" and r.get("arch") == info.arch),
        None,
    )
    if target_rpm is None:
        logger.warning(
            "Koji: kernel-debuginfo not found for %s/%s in build %d",
            nvr, info.arch, build_id,
        )
        return None

    # Construct the kojipkgs download URL:
    # https://kojipkgs.fedoraproject.org/packages/{name}/{version}/{release}/{arch}/{nvra}.rpm
    rpm_name = target_rpm["name"]         # "kernel-debuginfo"
    rpm_ver  = target_rpm["version"]      # "6.5.6"
    rpm_rel  = target_rpm["release"]      # "300.fc39"
    rpm_arch = target_rpm["arch"]         # "x86_64"
    filename = f"{rpm_name}-{rpm_ver}-{rpm_rel}.{rpm_arch}.rpm"
    url = f"{_KOJI_PKGS}/kernel/{rpm_ver}/{rpm_rel}/{rpm_arch}/{filename}"

    logger.info("Found Fedora debuginfo RPM: %s", url)
    return url


def _extract_vmlinux_rpm(rpm_path: Path, extract_dir: Path) -> Path | None:
    """
    Extract the RPM archive using rpm2cpio | cpio and find the vmlinux ELF.
    Returns the path to vmlinux, or None if not found.
    """
    rpm2cpio = subprocess.Popen(
        ["rpm2cpio", str(rpm_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    cpio_proc = subprocess.Popen(
        ["cpio", "-idmv"],
        stdin=rpm2cpio.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(extract_dir),
    )
    rpm2cpio.stdout.close()  # allow rpm2cpio to receive SIGPIPE if cpio exits

    cpio_proc.wait()
    rpm2cpio.wait()

    if rpm2cpio.returncode != 0:
        err = rpm2cpio.stderr.read().decode(errors="replace")
        logger.error("rpm2cpio failed (rc=%d): %s", rpm2cpio.returncode, err[:300])
        return None
    # cpio exits 2 on non-fatal warnings (e.g. hardlink issues) — treat as success
    if cpio_proc.returncode not in (0, 2):
        err = cpio_proc.stderr.read().decode(errors="replace")
        logger.error("cpio failed (rc=%d): %s", cpio_proc.returncode, err[:300])
        return None

    # vmlinux is at usr/lib/debug/lib/modules/<version>/vmlinux inside the RPM
    candidates = list(extract_dir.rglob("vmlinux"))
    if not candidates:
        logger.error("No vmlinux file found inside RPM at %s", rpm_path)
        return None
    vmlinux = max(candidates, key=lambda p: p.stat().st_size)
    logger.info("Using vmlinux: %s (%.1f MB)", vmlinux, vmlinux.stat().st_size / 1024 / 1024)
    return vmlinux


# ── RHEL-family helpers ───────────────────────────────────────────────────────


def _rhel_distro_order(banner: str) -> list[str]:
    """
    Return the list of distro keys to try, in order, based on the banner text.

    - CentOS banners → try centos first, then rocky, alma
    - Rocky banners  → try rocky first, then alma
    - AlmaLinux      → try alma first, then rocky
    - Red Hat / RHEL → no official free mirror; use rocky then alma as proxy
    """
    bl = banner.lower()
    if "centos" in bl:
        return ["centos", "rocky", "alma"]
    if "rocky" in bl:
        return ["rocky", "alma"]
    if "almalinux" in bl or "alma" in bl:
        return ["alma", "rocky"]
    # Red Hat / generic el banner — use Rocky then AlmaLinux as proxy
    return ["rocky", "alma"]


def _find_rpm_url_rhel(info: KernelInfo, banner: str) -> str | None:
    """
    Probe the HTTP-browsable debuginfo directories for each RHEL-family distro
    and return the first URL that responds with HTTP 200.

    info.version_extended = "4.18.0-477.10.1.el8_8"  (no arch suffix)
    """
    # Split version_extended into ver / rel components for the RPM filename.
    # "4.18.0-477.10.1.el8_8"  → ver="4.18.0", rel="477.10.1.el8_8"
    try:
        kver, krel = info.version_extended.split("-", 1)
    except ValueError:
        logger.warning("Cannot parse RHEL version_extended %r", info.version_extended)
        return None

    # Extract major EL version from release string, e.g. "el8" → "8"
    el_m = re.search(r"el(\d+)", krel)
    if not el_m:
        logger.warning("Cannot determine EL major version from %r", krel)
        return None
    major = el_m.group(1)

    distro_order = _rhel_distro_order(banner)
    arch = info.arch

    for distro in distro_order:
        for url_template in _RHEL_DEBUGINFO_URLS[distro]:
            url = url_template.format(major=major, arch=arch, ver=kver, rel=krel)
            try:
                resp = httpx.head(url, timeout=15, follow_redirects=True)
                if resp.status_code == 200:
                    logger.info(
                        "Found RHEL debuginfo RPM (%s): %s", distro, url
                    )
                    return url
                logger.debug("RHEL probe %s → %d", url, resp.status_code)
            except httpx.HTTPError as exc:
                logger.debug("RHEL probe failed for %s: %s", url, exc)

    logger.warning(
        "No RHEL debuginfo RPM found for %s / %s (tried: %s)",
        info.version_short, info.version_extended, distro_order,
    )
    return None


# ── snapshot.debian.org helpers ───────────────────────────────────────────────

_SNAPSHOT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json",
}


def _find_deb_url_debian(info: KernelInfo) -> str | None:
    """
    Locate the debug .deb on snapshot.debian.org for the given kernel.

    Tries two package name patterns:
      linux-image-{version_short}-dbg          (most common)
      linux-image-unsigned-{version_short}-dbg  (some amd64/arm64 kernels)

    Returns the direct download URL for the .deb file, or None if not found.
    """
    pkg_patterns = [
        f"linux-image-{info.version_short}-dbg",
        f"linux-image-unsigned-{info.version_short}-dbg",
    ]
    for pkg in pkg_patterns:
        url = f"{_SNAPSHOT_API}/binary/{pkg}/{info.version_extended}/binfiles"
        try:
            resp = httpx.get(url, headers=_SNAPSHOT_HEADERS, timeout=20, follow_redirects=True)
            if resp.status_code == 404:
                logger.debug("snapshot.debian.org: %s not found for version %s", pkg, info.version_extended)
                continue
            resp.raise_for_status()
            data = resp.json()
            results = data.get("result", [])
            if not results:
                logger.debug("snapshot.debian.org: empty result for %s %s", pkg, info.version_extended)
                continue
            # Pick the entry matching our arch (or take the first if only one)
            entry = next(
                (r for r in results if r.get("architecture") == info.arch),
                results[0],
            )
            file_hash = entry.get("hash") or entry.get("sha1")
            if not file_hash:
                logger.warning("snapshot.debian.org: no hash in result for %s", pkg)
                continue
            deb_url = f"{_SNAPSHOT_FILE}/{file_hash}"
            logger.info(
                "Found Debian dbg deb for %s/%s: %s (hash=%s)",
                info.version_short, info.version_extended, pkg, file_hash,
            )
            return deb_url
        except httpx.HTTPError as exc:
            logger.warning("snapshot.debian.org request failed for %s: %s", pkg, exc)
    return None


# ── Debuginfod helpers ────────────────────────────────────────────────────────


def _extract_build_id(dump_path: Path) -> str | None:
    """
    Try to extract the GNU build-ID from a memory dump.

    Strategy 1 — eu-readelf --notes:
      Works for ELF vmcore / kdump files; fast and authoritative.

    Strategy 2 — raw byte scan:
      Works for raw / LiME dumps.  Scans the first 64 MB for the
      NT_GNU_BUILD_ID ELF note pattern.  Handles both 20-byte (SHA1)
      and 32-byte (SHA256) build-IDs.

    Returns the build-ID as a lowercase hex string, or None.
    """
    # Strategy 1: eu-readelf
    try:
        result = subprocess.run(
            ["eu-readelf", "--notes", str(dump_path)],
            capture_output=True, timeout=30,
        )
        m = re.search(
            r"Build ID:\s+([0-9a-f]{40,64})",
            result.stdout.decode(errors="replace"),
        )
        if m:
            logger.debug("build-ID from eu-readelf: %s", m.group(1))
            return m.group(1)
    except FileNotFoundError:
        logger.debug("eu-readelf not found — falling back to raw scan")
    except subprocess.TimeoutExpired:
        logger.debug("eu-readelf timed out — falling back to raw scan")

    # Strategy 2: raw byte scan
    # ELF note layout (little-endian):
    #   offset -8: namesz (uint32) — 4 for "GNU\0"
    #   offset -4: descsz (uint32) — 20 (SHA1) or 32 (SHA256)
    #   offset  0: type   (uint32) — 3 = NT_GNU_BUILD_ID  ← _NOTE_TYPE_NAME starts here
    #   offset  4: name   (4 bytes) = "GNU\0"              ← _NOTE_TYPE_NAME ends here
    #   offset  8: build-ID bytes (descsz bytes)
    try:
        with dump_path.open("rb") as fh:
            data = fh.read(_DEBUGINFOD_SCAN_BYTES)
        pos = data.find(_NOTE_TYPE_NAME)
        if pos >= 4:
            descsz = int.from_bytes(data[pos - 4 : pos], "little")
            if descsz in (20, 32):
                build_id_bytes = data[pos + 8 : pos + 8 + descsz]
                if len(build_id_bytes) == descsz:
                    build_id = build_id_bytes.hex()
                    logger.debug("build-ID from raw scan: %s", build_id)
                    return build_id
    except OSError as exc:
        logger.debug("Raw build-ID scan failed: %s", exc)

    logger.debug("Could not extract build-ID from %s", dump_path)
    return None


def _fetch_debuginfod_elf(build_id: str, dest: Path) -> bool:
    """
    Try each debuginfod server in order and download the debuginfo ELF for
    the given build-ID to *dest*.

    Returns True if any server returned the file, False otherwise.
    Partial downloads are cleaned up on failure.
    """
    for server in _DEBUGINFOD_SERVERS:
        url = f"{server}/buildid/{build_id}/debuginfo"
        tmp = dest.with_suffix(".debuginfod.tmp")
        try:
            with httpx.stream("GET", url, timeout=120, follow_redirects=True) as resp:
                if resp.status_code != 200:
                    logger.debug("debuginfod %s → %d", url, resp.status_code)
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                with tmp.open("wb") as fh:
                    for chunk in resp.iter_bytes(chunk_size=1024 * 1024):
                        fh.write(chunk)
            tmp.rename(dest)
            logger.info(
                "debuginfod: fetched debuginfo ELF for build-ID %s from %s (%.1f MB)",
                build_id, server, dest.stat().st_size / 1024 / 1024,
            )
            return True
        except httpx.HTTPError as exc:
            logger.debug("debuginfod %s failed: %s", server, exc)
            tmp.unlink(missing_ok=True)

    return False


# ── Public entry point ────────────────────────────────────────────────────────

def symbol_cache_path(info: KernelInfo) -> Path:
    """Return the expected ISF path for this kernel (may or may not exist yet)."""
    linux_dir = Path(settings.SYMBOL_CACHE_PATH) / "linux"
    # Volatility3 finds symbols by matching the banner; use version_short as filename
    safe_name = info.version_short.replace("/", "_")
    return linux_dir / f"{safe_name}.json.xz"


def build_symbols_via_debuginfod(dump_path: Path, banner: str) -> Path | None:
    """
    Universal debuginfod fallback: extract the GNU build-ID from the dump,
    fetch the debuginfo ELF from a public debuginfod server, then run
    dwarf2json to produce the ISF.

    Works for any distro — the build-ID uniquely identifies the kernel binary
    regardless of distribution.

    Returns the Path to the generated ISF file, or None on failure.
    Idempotent: returns immediately if the ISF already exists.
    """
    # Determine ISF output path.  Use a distro parser if one matches so the
    # filename is consistent with what the other builders would produce.
    # Fall back to the raw version string for unrecognised distros.
    info = (
        parse_ubuntu_banner(banner)
        or parse_debian_banner(banner)
        or parse_fedora_banner(banner)
        or parse_rhel_banner(banner)
    )
    if info is not None:
        isf_path = symbol_cache_path(info)
        kernel_label = info.version_short
    else:
        m = _LINUX_VERSION_RE.search(banner)
        version_raw = m.group(1).replace("/", "_") if m else "unknown"
        isf_path = Path(settings.SYMBOL_CACHE_PATH) / "linux" / f"{version_raw}.json.xz"
        kernel_label = version_raw

    if isf_path.exists():
        logger.info("Symbol table already cached at %s", isf_path)
        return isf_path

    logger.info("Trying debuginfod fallback for kernel %s", kernel_label)

    build_id = _extract_build_id(dump_path)
    if not build_id:
        logger.info("Could not extract build-ID from dump — debuginfod fallback unavailable")
        return None

    logger.info("Extracted build-ID: %s", build_id)

    with tempfile.TemporaryDirectory(prefix="memoryscope_dbginfod_") as tmp:
        tmp_path = Path(tmp)
        elf_path = tmp_path / "vmlinux.debuginfo"

        if not _fetch_debuginfod_elf(build_id, elf_path):
            logger.info("debuginfod: no server had build-ID %s", build_id)
            return None

        try:
            _run_dwarf2json(elf_path, isf_path)
            _patch_linux_banner(isf_path, banner)
        except Exception:
            logger.exception(
                "debuginfod symbol build failed for %s — cleaning up", kernel_label
            )
            isf_path.unlink(missing_ok=True)
            return None

    return isf_path


def build_rhel_symbols(banner: str) -> Path | None:
    """
    Full pipeline for RHEL-family (CentOS / Rocky / AlmaLinux / RHEL):
    parse banner → probe distro debuginfo HTTP dirs → download RPM
    → rpm2cpio extraction → dwarf2json.

    Returns the Path to the generated ISF file, or None on failure.
    Idempotent: returns immediately if the ISF already exists.
    """
    info = parse_rhel_banner(banner)
    if info is None:
        logger.info("Banner is not RHEL-family — skipping RHEL symbol build")
        return None

    isf_path = symbol_cache_path(info)
    if isf_path.exists():
        logger.info("Symbol table already cached at %s", isf_path)
        return isf_path

    logger.info(
        "Building RHEL-family symbol table for %s (%s, %s)",
        info.version_short, info.version_extended, info.arch,
    )

    rpm_url = _find_rpm_url_rhel(info, banner)
    if not rpm_url:
        logger.error(
            "Could not find kernel-debuginfo RPM for RHEL kernel %s / %s",
            info.version_short, info.version_extended,
        )
        return None

    with tempfile.TemporaryDirectory(prefix="memoryscope_sym_") as tmp:
        tmp_path = Path(tmp)
        rpm_path = tmp_path / "kernel-debuginfo.rpm"
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        try:
            _download_file(rpm_url, rpm_path)
            vmlinux = _extract_vmlinux_rpm(rpm_path, extract_dir)
            if vmlinux is None:
                return None
            _run_dwarf2json(vmlinux, isf_path)
            _patch_linux_banner(isf_path, banner)
        except Exception:
            logger.exception(
                "RHEL symbol build failed for %s — cleaning up partial output",
                info.version_short,
            )
            if isf_path.exists():
                isf_path.unlink(missing_ok=True)
            return None

    return isf_path


def build_fedora_symbols(banner: str) -> Path | None:
    """
    Full pipeline for Fedora: parse banner → find kernel-debuginfo RPM via Koji
    → download → rpm2cpio extraction → dwarf2json.

    Returns the Path to the generated ISF file, or None on failure.
    Idempotent: returns immediately if the ISF already exists.
    """
    info = parse_fedora_banner(banner)
    if info is None:
        logger.info("Banner is not Fedora — skipping Fedora symbol build")
        return None

    isf_path = symbol_cache_path(info)
    if isf_path.exists():
        logger.info("Symbol table already cached at %s", isf_path)
        return isf_path

    logger.info(
        "Building Fedora symbol table for %s (%s, %s)",
        info.version_short, info.version_extended, info.arch,
    )

    rpm_url = _find_rpm_url_fedora(info)
    if not rpm_url:
        logger.error(
            "Could not find kernel-debuginfo RPM for Fedora kernel %s / %s",
            info.version_short, info.version_extended,
        )
        return None

    with tempfile.TemporaryDirectory(prefix="memoryscope_sym_") as tmp:
        tmp_path = Path(tmp)
        rpm_path = tmp_path / "kernel-debuginfo.rpm"
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        try:
            _download_file(rpm_url, rpm_path)
            vmlinux = _extract_vmlinux_rpm(rpm_path, extract_dir)
            if vmlinux is None:
                return None
            _run_dwarf2json(vmlinux, isf_path)
            _patch_linux_banner(isf_path, banner)
        except Exception:
            logger.exception(
                "Fedora symbol build failed for %s — cleaning up partial output",
                info.version_short,
            )
            if isf_path.exists():
                isf_path.unlink(missing_ok=True)
            return None

    return isf_path


def build_debian_symbols(banner: str) -> Path | None:
    """
    Full pipeline for Debian: parse banner → find .deb on snapshot.debian.org
    → download → extract → dwarf2json.

    Returns the Path to the generated ISF file, or None on failure.
    Idempotent: returns immediately if the ISF already exists.
    """
    info = parse_debian_banner(banner)
    if info is None:
        logger.info("Banner is not Debian — skipping Debian symbol build")
        return None

    isf_path = symbol_cache_path(info)
    if isf_path.exists():
        logger.info("Symbol table already cached at %s", isf_path)
        return isf_path

    logger.info(
        "Building Debian symbol table for %s (%s, %s)",
        info.version_short, info.version_extended, info.arch,
    )

    deb_url = _find_deb_url_debian(info)
    if not deb_url:
        logger.error(
            "Could not find debug .deb for Debian kernel %s / %s on snapshot.debian.org",
            info.version_short, info.version_extended,
        )
        return None

    with tempfile.TemporaryDirectory(prefix="memoryscope_sym_") as tmp:
        tmp_path = Path(tmp)
        deb_path = tmp_path / "kernel-dbg.deb"
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        try:
            _download_file(deb_url, deb_path)
            vmlinux = _extract_vmlinux(deb_path, extract_dir)
            if vmlinux is None:
                return None
            _run_dwarf2json(vmlinux, isf_path)
            _patch_linux_banner(isf_path, banner)
        except Exception:
            logger.exception(
                "Debian symbol build failed for %s — cleaning up partial output",
                info.version_short,
            )
            if isf_path.exists():
                isf_path.unlink(missing_ok=True)
            return None

    return isf_path


def build_ubuntu_symbols(banner: str) -> Path | None:
    """
    Full pipeline: parse banner → find ddeb → download → extract → dwarf2json.

    Returns the Path to the generated ISF file, or None on failure.
    The function is idempotent: if the ISF already exists, it is returned immediately.
    """
    info = parse_ubuntu_banner(banner)
    if info is None:
        logger.info("Banner is not Ubuntu — skipping symbol build")
        return None

    isf_path = symbol_cache_path(info)
    if isf_path.exists():
        logger.info("Symbol table already cached at %s", isf_path)
        return isf_path

    logger.info(
        "Building symbol table for %s (%s, %s)",
        info.version_short, info.version_extended, info.arch,
    )

    series = _get_ubuntu_releases()
    ddeb_url = _find_ddeb_url(info, series)
    if not ddeb_url:
        logger.error(
            "Could not find ddeb for kernel %s / %s on Launchpad",
            info.version_short, info.version_extended,
        )
        return None

    with tempfile.TemporaryDirectory(prefix="memoryscope_sym_") as tmp:
        tmp_path = Path(tmp)
        ddeb_path = tmp_path / "kernel.ddeb"
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        try:
            _download_file(ddeb_url, ddeb_path)
            vmlinux = _extract_vmlinux(ddeb_path, extract_dir)
            if vmlinux is None:
                return None
            _run_dwarf2json(vmlinux, isf_path)
            _patch_linux_banner(isf_path, banner)
        except Exception:
            logger.exception(
                "Symbol build failed for %s — cleaning up partial output", info.version_short
            )
            if isf_path.exists():
                isf_path.unlink(missing_ok=True)
            return None

    return isf_path
