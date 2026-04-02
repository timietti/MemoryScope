# backend/core/plugins/parsers/base.py
"""
Base parser class. Each Volatility3 plugin has a typed parser that converts
raw JSON output into a normalised, AI-friendly schema.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any


class BaseParser(ABC):
    """
    Parse Volatility3 --output json data into a typed list of dicts.
    
    Volatility3 JSON format:
    {
        "columns": ["Name", "PID", "PPID", ...],
        "rows": [[value, value, ...], ...]
    }
    """

    def parse(self, data: dict | list) -> list[dict]:
        """Convert raw Volatility3 JSON output to list of typed records.

        Handles two formats emitted by different Volatility3 versions:
          - List of row-dicts:  [{col: val, ...}, ...]          (v2.x -r json)
          - Columns/rows dict:  {"columns": [...], "rows": [[...],...]}
        """
        # v2.x list format
        if isinstance(data, list):
            records = []
            for row in data:
                if isinstance(row, dict):
                    normalised = self.normalise({k: _clean(v) for k, v in row.items()
                                                 if not k.startswith("__")})
                    if normalised:
                        records.append(normalised)
            return records

        # Legacy columns/rows dict format
        columns = data.get("columns", [])
        rows = data.get("rows", [])

        if not columns or rows is None:
            return []

        records = []
        for row in rows:
            if isinstance(row, dict):
                record = row
            elif isinstance(row, list):
                record = dict(zip(columns, row))
            else:
                continue

            normalised = self.normalise(record)
            if normalised:
                records.append(normalised)

        return records

    def normalise(self, record: dict) -> dict | None:
        """
        Override to transform a single row dict into the target schema.
        Return None to skip the record (e.g. filter noise).
        Default: return as-is with string-cleaned values.
        """
        return {k: _clean(v) for k, v in record.items()}

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        """
        Return an AI-ready filtered view of parsed rows.
        Default: return first max_rows rows with a summary header.
        Override in subclasses to apply domain-specific noise reduction.
        """
        flagged = [r for r in rows if any(
            r.get(k) for k in r if k.startswith("is_") and r.get(k) is True
        )]
        display = flagged[:max_rows] if flagged else rows[:max_rows]
        note = (
            f"Showing {len(display)} of {len(rows)} rows"
            + (f" ({len(flagged)} flagged)" if flagged else "")
            + ("." if len(display) >= len(rows) else f"; {len(rows) - len(display)} rows omitted.")
        )
        return {
            "total_rows": len(rows),
            "flagged_rows": len(flagged),
            "rows": display,
            "filter_note": note,
        }


def _clean(value: Any) -> Any:
    """Convert Volatility3 special values to clean Python types."""
    if value is None or value == "-" or value == "N/A":
        return None
    if isinstance(value, str):
        return value.strip() or None
    return value


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/pslist.py

class PslistParser(BaseParser):
    """
    Normalise windows.pslist / linux.pslist / mac.pslist output.
    
    Output schema:
    {
        "pid": int, "ppid": int, "name": str,
        "offset": str (hex), "threads": int, "handles": int,
        "wow64": bool, "create_time": str, "exit_time": str,
        "path": str | None
    }
    """

    def normalise(self, record: dict) -> dict | None:
        pid  = record.get("PID") or record.get("Pid")
        ppid = record.get("PPID") or record.get("PPid")
        name = record.get("ImageFileName") or record.get("COMM") or record.get("Name")

        if not pid:
            return None

        return {
            "pid": _int(pid),
            "ppid": _int(ppid),
            "name": _str(name),
            "offset": _hex(record.get("OFFSET (V)") or record.get("OFFSET (P)") or record.get("OFFSET") or record.get("Offset(V)") or record.get("Offset")),
            "threads": _int(record.get("Threads") or record.get("ActiveThreads")),
            "handles": _int(record.get("Handles")),
            "session_id": _int(record.get("SessionId")),
            "wow64": _bool(record.get("Wow64")),
            "create_time": _str(record.get("CREATION TIME") or record.get("CreateTime")),
            "exit_time": _str(record.get("ExitTime")),
            "exit_state": _str(record.get("EXIT_STATE")),
            "uid": _int(record.get("UID")),
            "gid": _int(record.get("GID")),
            "euid": _int(record.get("EUID")),
            "egid": _int(record.get("EGID")),
            "tid": _int(record.get("TID")),
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/malfind.py

class MalfindParser(BaseParser):
    """
    Normalise windows.malfind output — injected code detection.
    
    Output schema per suspicious region:
    {
        "pid": int, "process": str, "start": str, "end": str,
        "vad_tag": str, "protection": str, "protection_flags": list[str],
        "disasm": str | None, "hexdump": str | None,
        "has_pe_header": bool
    }
    """

    # VAD protection flags that indicate suspicious executable memory (Windows)
    SUSPICIOUS_PROTECTIONS = {
        "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",
        "PAGE_EXECUTE_READ_WRITE",  # non-standard variant
    }

    def normalise(self, record: dict) -> dict | None:
        protection = _str(record.get("Protection") or record.get("Vad.Protection"))

        # Linux malfind uses POSIX-style flags ("rwx"); Windows uses PAGE_* constants.
        # malfind already pre-filters to suspicious regions, so only drop records
        # that have a non-suspicious Windows protection AND no PE header.
        is_linux_rwx = bool(protection and "x" in protection and "w" in protection)
        is_windows_suspicious = protection in self.SUSPICIOUS_PROTECTIONS
        if not is_linux_rwx and not is_windows_suspicious:
            disasm = _str(record.get("Disasm") or record.get("Disassembly"))
            hexdump = _str(record.get("Hexdump"))
            has_pe = bool(hexdump and ("4d 5a" in hexdump.lower() or "MZ" in (hexdump or "")))
            if not has_pe:
                return None

        disasm = _str(record.get("Disasm") or record.get("Disassembly"))
        hexdump = _str(record.get("Hexdump"))
        has_pe = bool(hexdump and ("4d 5a" in hexdump.lower()))

        prot_flags = []
        if protection:
            prot_flags = [f.strip() for f in protection.split("|")]

        return {
            "pid": _int(record.get("PID") or record.get("Pid")),
            "process": _str(record.get("Process") or record.get("ImageFileName")),
            "start": _hex(record.get("Start VPN") or record.get("Start")),
            "end": _hex(record.get("End VPN") or record.get("End")),
            "path": _str(record.get("Path") or record.get("Filename")),
            "vad_tag": _str(record.get("Tag")),
            "protection": protection,
            "protection_flags": prot_flags,
            "disasm_snippet": disasm[:500] if disasm else None,
            "hexdump_snippet": hexdump[:200] if hexdump else None,
            "has_pe_header": has_pe,
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/netstat.py

class NetstatParser(BaseParser):
    """
    Normalise windows.netstat / windows.netscan / linux.netstat output.
    
    {
        "pid": int, "process": str, "protocol": str,
        "local_addr": str, "local_port": int,
        "remote_addr": str, "remote_port": int,
        "state": str, "create_time": str | None
    }
    """

    PRIVATE_RANGES = (
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.2", "172.3", "192.168.", "127.", "0.0.0.0",
        "::", "fe80:",
    )

    def normalise(self, record: dict) -> dict | None:
        proto = _str(record.get("Proto") or record.get("Protocol"))

        # linux.sockstat has separate addr/port fields; windows.netstat combines them
        if "Source Addr" in record or "Destination Addr" in record:
            local_addr = _str(record.get("Source Addr"))
            local_port = _int(record.get("Source Port"))
            remote_addr = _str(record.get("Destination Addr"))
            remote_port = _int(record.get("Destination Port"))
            # Enrich proto with family/type for sockstat
            family = _str(record.get("Family"))
            sock_type = _str(record.get("Type"))
            if family and not proto:
                proto = f"{family}/{sock_type}" if sock_type else family
            elif family and proto:
                proto = f"{family}/{proto}"
        elif "LocalPort" in record or "ForeignPort" in record:
            # windows.netstat / windows.netscan: separate addr and port fields
            local_addr  = _str(record.get("LocalAddr")   or record.get("Laddr"))
            local_port  = _int(record.get("LocalPort"))
            remote_addr = _str(record.get("ForeignAddr") or record.get("FAddr") or record.get("Raddr"))
            remote_port = _int(record.get("ForeignPort"))
        else:
            local  = _str(record.get("LocalAddr") or record.get("Laddr"))
            remote = _str(record.get("ForeignAddr") or record.get("FAddr") or record.get("Raddr"))
            local_addr, local_port = _split_addr(local)
            remote_addr, remote_port = _split_addr(remote)

        is_external = remote_addr and not any(
            remote_addr.startswith(p) for p in self.PRIVATE_RANGES
        )

        return {
            "pid": _int(record.get("PID") or record.get("Pid")),
            "process": _str(record.get("Process Name") or record.get("Owner") or record.get("Process")),
            "protocol": proto,
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "state": _str(record.get("State")),
            "create_time": _str(record.get("Created") or record.get("CreateTime")),
            "is_external": bool(is_external),
        }


def _split_addr(addr: str | None) -> tuple[str | None, int | None]:
    """Split '192.168.1.1:443' or '[::1]:80' into (ip, port)."""
    if not addr or addr in ("-", "*:*"):
        return None, None
    try:
        if addr.startswith("["):  # IPv6
            bracket_end = addr.index("]")
            ip = addr[1:bracket_end]
            port = int(addr[bracket_end+2:]) if bracket_end+2 < len(addr) else None
        elif ":" in addr:
            parts = addr.rsplit(":", 1)
            ip = parts[0]
            port = int(parts[1]) if parts[1].isdigit() else None
        else:
            ip = addr
            port = None
        return ip or None, port
    except (ValueError, IndexError):
        return addr, None


# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/registry.py

class RegistryParser(BaseParser):
    """windows.registry.hivelist / windows.registry.printkey"""

    def normalise(self, record: dict) -> dict | None:
        return {
            "hive_offset": _hex(record.get("Offset") or record.get("HiveOffset")),
            "file_full_path": _str(record.get("FileFullPath") or record.get("HiveName")),
            "key": _str(record.get("Key")),
            "last_write": _str(record.get("LastWriteTime")),
            "value_name": _str(record.get("Name")),
            "value_type": _str(record.get("Type")),
            "value_data": _str(record.get("Data")),
            "volatile": _bool(record.get("Volatile")),
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/pstree.py

class PstreeParser(BaseParser):
    def parse(self, data: dict | list) -> list[dict]:
        """Flatten the nested __children tree into a single list with depth tracking."""
        if not isinstance(data, list):
            return super().parse(data)

        results: list[dict] = []

        def _walk(nodes: list, depth: int) -> None:
            for row in nodes:
                if not isinstance(row, dict):
                    continue
                children = row.get("__children", [])
                clean = {k: _clean(v) for k, v in row.items() if not k.startswith("__")}
                normalised = self.normalise(clean)
                if normalised is not None:
                    normalised["depth"] = depth
                    results.append(normalised)
                if children:
                    _walk(children, depth + 1)

        _walk(data, 0)
        return results

    def normalise(self, record: dict) -> dict | None:
        offset_raw = (
            record.get("OFFSET (V)")
            or record.get("Offset(V)")
            or record.get("Offset")
        )
        return {
            "pid": _int(record.get("PID") or record.get("Pid")),
            "ppid": _int(record.get("PPID") or record.get("PPid")),
            "name": _str(record.get("ImageFileName") or record.get("Name") or record.get("COMM")),
            "offset": _hex(offset_raw),
            "threads": _int(record.get("Threads")),
            "handles": _int(record.get("Handles")),
            "wow64": _bool(record.get("Wow64")),
            "create_time": _str(record.get("CreateTime")),
            "depth": 0,
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/cmdline.py

class CmdlineParser(BaseParser):
    def normalise(self, record: dict) -> dict | None:
        cmdline = _str(record.get("Args") or record.get("CommandLine"))
        return {
            "pid": _int(record.get("PID") or record.get("Pid")),
            "process": _str(record.get("Process") or record.get("ImageFileName")),
            "cmdline": cmdline,
            "has_encoded_payload": _detect_encoded(cmdline),
        }


def _detect_encoded(cmdline: str | None) -> bool:
    """Heuristic: detect Base64-encoded or heavily obfuscated PowerShell payloads."""
    import re
    if not cmdline:
        return False
    lower = cmdline.lower()
    indicators = [
        "-enc ", "-encodedcommand", "frombase64string",
        "invoke-expression", "iex(", "invoke-webrequest",
        "downloadstring", "hidden", "-w hidden", "-windowstyle hidden",
    ]
    if any(ind in lower for ind in indicators):
        return True
    # Detect a raw Base64 blob: 40+ consecutive Base64 characters.
    # File paths and normal args contain \, :, spaces etc. which break the run,
    # so a long unbroken Base64 sequence is a strong signal of an encoded payload.
    if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', cmdline):
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/dlllist.py

class DlllistParser(BaseParser):
    # Known-clean system paths (reduce noise)
    SYSTEM_PATHS = (
        r"c:\windows\system32",
        r"c:\windows\syswow64",
        r"c:\windows\winsxs",
        r"c:\program files",
    )

    def normalise(self, record: dict) -> dict | None:
        path = _str(record.get("Path") or record.get("FullName"))
        path_lower = (path or "").lower()
        is_system = any(path_lower.startswith(p) for p in self.SYSTEM_PATHS)

        return {
            "pid": _int(record.get("PID") or record.get("Pid")),
            "process": _str(record.get("Process")),
            "base": _hex(record.get("Base")),
            "size": _int(record.get("Size")),
            "name": _str(record.get("Name")),
            "path": path,
            "is_system_path": is_system,
            "load_reason": _str(record.get("LoadReason")),
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        interesting = [r for r in rows if not r.get("is_system_path") or not r.get("path")]
        note = (
            f"{len(interesting)} non-system-path DLLs of {len(rows)} total. "
            f"Showing first {min(len(interesting), max_rows)}."
        )
        return {
            "total_rows": len(rows),
            "flagged_rows": len(interesting),
            "rows": interesting[:max_rows],
            "filter_note": note,
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/handles.py

class HandlesParser(BaseParser):
    # Mutex names known to be used by malware families
    KNOWN_BAD_MUTEXES = {
        # ZeuS / KINS / Citadel banking trojans
        "Global\\MsWinZonesCacheCounterMutexA",
        "Global\\MsWinZonesCacheCounterMutexA0",
        "Global\\MsWinZonesCacheCounterMutexA1",
        "ZupdService",
        # ZeuS/SpyEye AV evasion markers
        "_AVIRA_", "_AVIRA_2109", "IESQMMUTEX",
        # Gh0st RAT variants
        "Gh0st135", "cb0a7fa0-0c8d-11e2-8f4c-00267cb68e0e",
        # njRAT / Bladabindi
        "njq8",
        # WannaCry ransomware
        "WNcry@2ol7",
        # DarkComet RAT
        "DC_MUTEX-",
        # Poison Ivy RAT
        "PoisonIvy", "POISONIVY",
        # Xtreme RAT
        "MutexGlobalXtremeRat",
        # AsyncRAT
        "AsyncMutex_6SI8OkPnk",
        # QuasarRAT
        "Quasar Server Mutex",
        # Emotet loader (early versions)
        "Global\\I386", "Global\\M386",
        # BlackEnergy
        "Global\\Gsc",
        # Remcos RAT
        "Remcos_Mutex_Inj",
        # NanoCore RAT
        "NanoCore Mutex",
        # CobaltStrike default named-pipe artefact appearing as mutex
        "Global\\msagent_",
    }

    # Handle types to always keep (regardless of process)
    _KEEP_TYPES = frozenset({"Mutant", "Section", "File", "Process", "Thread"})
    # Types that are always noise — drop entirely
    _DROP_TYPES = frozenset({"ALPC Port", "Desktop", "WindowStation", "TpWorkerFactory",
                              "IRTimer", "EtwRegistration", "WaitCompletionPacket"})
    # File path fragments that are interesting
    _INTERESTING_PATH_FRAGMENTS = (
        "\\temp\\", "\\tmp\\", "\\appdata\\", "\\users\\", "\\programdata\\",
        "\\device\\physicalMemory", "\\device\\rawdisk", "\\device\\harddisk",
        "\\pipe\\", "\\mailslot\\",
    )
    # System file path substrings to exclude (volume number varies, so use 'in' not startswith)
    _SYSTEM_PATH_FRAGMENTS = (
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\windows\\winsxs\\",
    )

    def normalise(self, record: dict) -> dict | None:
        handle_type = _str(record.get("Type") or record.get("HandleType"))
        name = _str(record.get("Name") or record.get("HandleName"))
        is_suspicious = name in self.KNOWN_BAD_MUTEXES if name else False

        return {
            "pid": _int(record.get("PID") or record.get("Pid")),
            "process": _str(record.get("Process")),
            "handle_value": _hex(record.get("HandleValue") or record.get("Handle")),
            "handle_type": handle_type,
            "name": name,
            "is_known_bad": is_suspicious,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        kept = []
        for r in rows:
            if r.get("is_known_bad"):
                kept.append(r)
                continue
            handle_type = (r.get("handle_type") or "").strip()
            if handle_type in self._DROP_TYPES:
                continue
            name = (r.get("name") or "").lower()
            if handle_type == "File":
                # Normalise double backslashes (Python repr artefact) to single
                path_norm = name.replace("\\\\", "\\")
                # Drop known-noisy system paths first, regardless of other matches
                if any(p in path_norm for p in self._SYSTEM_PATH_FRAGMENTS):
                    continue
                # Keep only handles to interesting locations
                if any(p in path_norm for p in self._INTERESTING_PATH_FRAGMENTS):
                    kept.append(r)
            elif handle_type == "Mutant":
                kept.append(r)  # Always keep all mutexes
            elif handle_type in self._KEEP_TYPES:
                kept.append(r)

        note = (
            f"Filtered from {len(rows)} to {len(kept)} handles "
            f"(dropped ALPC/Desktop/WindowStation/timer noise, retained Mutant/pipe/suspicious-path handles)."
            f" Showing first {min(len(kept), max_rows)}."
        )
        return {
            "total_rows": len(rows),
            "flagged_rows": sum(1 for r in kept if r.get("is_known_bad")),
            "rows": kept[:max_rows],
            "filter_note": note,
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/filescan.py

class FilescanParser(BaseParser):
    SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js"}
    SUSPICIOUS_PATHS = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "\\recycler\\",
                        "\\downloads\\", "\\desktop\\", "\\public\\")
    # Executables/DLLs in these paths are considered known-good
    TRUSTED_PATHS = ("\\windows\\system32\\", "\\windows\\syswow64\\",
                     "\\windows\\systemapps\\", "\\windows\\winsxs\\",
                     "\\program files\\", "\\program files (x86)\\")

    def normalise(self, record: dict) -> dict | None:
        import os
        name = _str(record.get("Name") or record.get("FileName"))
        name_lower = (name or "").lower()

        ext = os.path.splitext(name_lower)[1] if name_lower else ""
        in_trusted_path = any(p in name_lower for p in self.TRUSTED_PATHS)
        # Suspicious path always wins regardless of directory
        is_suspicious_path = any(p in name_lower for p in self.SUSPICIOUS_PATHS)
        # Executable extension is only suspicious outside trusted system directories
        is_suspicious_ext = ext in self.SUSPICIOUS_EXTENSIONS and not in_trusted_path

        return {
            "offset": _hex(record.get("Offset")),
            "pointers": _int(record.get("#Pnts") or record.get("PointerCount")),
            "handles": _int(record.get("#Hnd") or record.get("HandleCount")),
            "access": _str(record.get("Access")),
            "name": name,
            "is_suspicious": is_suspicious_ext or is_suspicious_path,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        suspicious = [r for r in rows if r.get("is_suspicious")]
        note = (
            f"{len(suspicious)} suspicious of {len(rows)} total file objects "
            f"(suspicious = executable/script in temp/downloads/appdata path). "
            f"Showing first {min(len(suspicious), max_rows)}."
        )
        return {
            "total_rows": len(rows),
            "flagged_rows": len(suspicious),
            "rows": suspicious[:max_rows],
            "filter_note": note,
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/hashdump.py

class JoblinksParser(BaseParser):
    """
    windows.joblinks

    Each top-level record is a job group with Active/Total process counts.
    The full executable path is in the first child whose Process field is not
    "(Original Process)".
    """

    def normalise(self, record: dict) -> dict | None:
        # Skip child rows — we only emit one row per job group (the parent)
        if record.get("JobLink") == "Yes":
            return None

        name = _str(record.get("Name"))
        pid  = _int(record.get("PID") or record.get("Pid"))

        # Extract full path from children
        path = None
        for child in record.get("__children") or []:
            p = _str(child.get("Process"))
            if p and p != "(Original Process)":
                path = p
                break

        return {
            "pid":         pid,
            "ppid":        _int(record.get("PPID") or record.get("PPid")),
            "name":        name,
            "path":        path,
            "active":      _int(record.get("Active")),
            "total":       _int(record.get("Total")),
            "session":     _int(record.get("Sess") or record.get("JobSess")),
            "wow64":       bool(record.get("Wow64")),
        }


class AmcacheParser(BaseParser):
    """
    windows.registry.amcache

    Schema: path, sha1, company, entry_type, install_time, last_modify_time,
            product_name, product_version, service, is_suspicious
    """
    _TRUSTED_PATHS = (
        "c:/windows/system32/", "c:/windows/syswow64/",
        "c:/windows/systemapps/", "c:/windows/winsxs/",
        "c:/program files/", "c:/program files (x86)/",
    )
    _SUSPICIOUS_PATHS = (
        "/temp/", "/tmp/", "/appdata/", "/downloads/",
        "/desktop/", "/public/", "/recycler/",
        "/appdata/local/temp/",
    )
    _TRUSTED_COMPANIES = frozenset({
        "microsoft corporation", "microsoft windows",
        "apple inc.", "advanced micro devices, inc",
        "advanced micro devices", "amd technologies inc.",
        "pmc-sierra", "lsi",
    })

    def normalise(self, record: dict) -> dict | None:
        path = _str(record.get("Path")) or ""
        path_lower = path.lower().replace("\\", "/")
        company = _str(record.get("Company")) or ""
        company_lower = company.lower()

        in_trusted = any(path_lower.startswith(p) for p in self._TRUSTED_PATHS)
        in_suspicious = any(p in path_lower for p in self._SUSPICIOUS_PATHS)
        unknown_company = not company_lower
        untrusted_company = (
            bool(company_lower)
            and not in_trusted
            and company_lower not in self._TRUSTED_COMPANIES
        )

        is_suspicious = in_suspicious or (not in_trusted and (unknown_company or untrusted_company))

        return {
            "path":              path,
            "sha1":              _str(record.get("SHA1")),
            "company":           company or None,
            "entry_type":        _str(record.get("EntryType")),
            "install_time":      _str(record.get("InstallTime")),
            "last_modify_time":  _str(record.get("LastModifyTime")),
            "product_name":      _str(record.get("ProductName")),
            "product_version":   _str(record.get("ProductVersion")),
            "service":           _str(record.get("Service")),
            "is_suspicious":     is_suspicious,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 200) -> dict:
        suspicious = [r for r in rows if r.get("is_suspicious")]
        note = (
            f"{len(suspicious)} suspicious of {len(rows)} total amcache entries "
            f"(suspicious = outside system32/program files, or unknown/untrusted company). "
            f"Showing first {min(len(suspicious), max_rows)}."
        )
        return {
            "total_rows":    len(rows),
            "flagged_rows":  len(suspicious),
            "rows":          suspicious[:max_rows],
            "filter_note":   note,
        }


class CmdscanParser(BaseParser):
    """
    windows.cmdscan

    The plugin emits one parent _COMMAND_HISTORY row per console session with
    named property children. This parser flattens the tree into one record per
    console session.

    Schema: pid, process, application, command_count, commands,
            has_encoded_payload
    """

    def parse(self, data: dict | list) -> list[dict]:
        rows: list = data if isinstance(data, list) else data.get("rows", [])
        records = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            children = row.get("__children") or []
            # Build a flat dict from child properties: strip "_COMMAND_HISTORY." prefix
            props: dict = {}
            for child in children:
                if not isinstance(child, dict):
                    continue
                prop = _str(child.get("Property")) or ""
                suffix = prop.split(".", 1)[1] if "." in prop else prop
                props[suffix] = _clean(child.get("Data"))
            record = {
                "PID":     _clean(row.get("PID")),
                "Process": _clean(row.get("Process")),
                **props,
            }
            normalised = self.normalise(record)
            if normalised:
                records.append(normalised)
        return records

    def normalise(self, record: dict) -> dict | None:
        commands_raw = _str(record.get("CommandBucket")) or ""
        # Commands may be newline- or pipe-separated; split into a list
        commands = [c.strip() for c in commands_raw.replace("|", "\n").splitlines() if c.strip()]
        cmd_text = " | ".join(commands) if commands else None
        return {
            "pid":                _int(record.get("PID")),
            "process":            _str(record.get("Process")),
            "application":        _str(record.get("Application")),
            "command_count":      _int(record.get("CommandCount")),
            "commands":           commands,
            "has_encoded_payload": _detect_encoded(cmd_text),
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 200) -> dict:
        # Only sessions that recorded at least one command are interesting
        with_cmds = [r for r in rows if r.get("command_count") or r.get("commands")]
        encoded   = [r for r in with_cmds if r.get("has_encoded_payload")]
        note = (
            f"{len(rows)} console sessions total; "
            f"{len(with_cmds)} have recorded commands; "
            f"{len(encoded)} contain encoded/obfuscated payloads."
        )
        return {
            "total_rows":   len(rows),
            "flagged_rows": len(encoded),
            "rows":         with_cmds[:max_rows],
            "filter_note":  note,
        }


class UserAssistParser(BaseParser):
    """
    windows.registry.userassist

    The plugin emits parent Key rows with __children Value rows. This parser
    overrides parse() to flatten that tree. Each child Value becomes one record.

    Schema: name, user, count, focus_count, time_focused, last_updated,
            hive_name, is_suspicious
    """
    _INTERNAL_NAMES = frozenset({
        "ueme_ctlcuacount:ctor",
        "ueme_ctlsession",
    })
    _SUSPICIOUS_PATHS = (
        "/downloads/", "/desktop/", "/temp/", "/tmp/",
        "/appdata/local/temp/", "/appdata/roaming/",
        "/public/", "/recycler/",
    )
    _TRUSTED_PATHS = (
        "%windir%", "%systemroot%",
        "c:/windows/", "c:/program files/", "c:/program files (x86)/",
    )

    def parse(self, data: dict | list) -> list[dict]:
        """Flatten parent Key rows → child Value rows."""
        import re
        rows: list = data if isinstance(data, list) else data.get("rows", [])
        records = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            children = row.get("__children") or []
            src_rows = [c for c in children if isinstance(c, dict) and c.get("Type") == "Value"]
            # If no children, handle a top-level Value row directly
            if not src_rows and row.get("Type") == "Value":
                src_rows = [row]
            for child in src_rows:
                normalised = self.normalise({k: _clean(v) for k, v in child.items()
                                             if not k.startswith("__")})
                if normalised:
                    records.append(normalised)
        return records

    def normalise(self, record: dict) -> dict | None:
        import re
        name = _str(record.get("Name")) or ""
        if not name or name.lower() in self._INTERNAL_NAMES:
            return None

        hive_name = _str(record.get("Hive Name")) or ""
        user: str | None = None
        m = re.search(r'[/\\][Uu]sers[/\\]([^/\\]+)', hive_name)
        if m:
            user = m.group(1)

        # Determine if name looks like a file-system path
        name_lower = name.lower().replace("\\", "/")
        is_path = (
            re.match(r'^[a-z]:', name_lower) is not None
            or name_lower.startswith("%")
            or name_lower.startswith("//")
            or name_lower.startswith("/")
        )
        in_trusted    = any(name_lower.startswith(p) for p in self._TRUSTED_PATHS)
        in_suspicious = any(p in name_lower for p in self._SUSPICIOUS_PATHS)
        is_suspicious = is_path and (in_suspicious or not in_trusted)

        return {
            "name":          name,
            "user":          user,
            "count":         _int(record.get("Count")),
            "focus_count":   _int(record.get("Focus Count")),
            "time_focused":  _str(record.get("Time Focused")),
            "last_updated":  _str(record.get("Last Updated")),
            "hive_name":     hive_name or None,
            "is_suspicious": is_suspicious,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 200) -> dict:
        suspicious = [r for r in rows if r.get("is_suspicious")]
        rest       = [r for r in rows if not r.get("is_suspicious")]
        combined   = suspicious + rest
        note = (
            f"{len(rows)} UserAssist execution entries across all hives; "
            f"{len(suspicious)} flagged suspicious (file-system paths outside "
            f"Windows/ProgramFiles). Suspicious entries shown first."
        )
        return {
            "total_rows":   len(rows),
            "flagged_rows": len(suspicious),
            "rows":         combined[:max_rows],
            "filter_note":  note,
        }


class ScheduledTasksParser(BaseParser):
    """
    windows.registry.scheduled_tasks

    Schema: task_name, key_name, action, action_arguments, action_type,
            action_context, trigger_type, trigger_description, enabled,
            last_run_time, last_successful_run_time, working_directory,
            is_suspicious
    """
    _SUSPICIOUS_PATHS = (
        "/temp/", "/tmp/", "/appdata/", "/downloads/",
        "/desktop/", "/public/", "/recycler/", "/users/",
    )
    _TRUSTED_PATHS = (
        "%windir%", "%systemroot%",
        "c:/windows/", "c:/program files/", "c:/program files (x86)/",
    )
    _SUSPICIOUS_EXTS = (".bat", ".ps1", ".vbs", ".js", ".cmd", ".hta", ".jar", ".wsf", ".jse", ".psc1")

    def normalise(self, record: dict) -> dict | None:
        action      = _str(record.get("Action")) or ""
        action_type = _str(record.get("Action Type")) or ""
        enabled     = record.get("Enabled")

        is_suspicious = False
        if action_type == "Exe":
            a_lower = action.lower().replace("\\", "/")
            in_trusted    = any(a_lower.startswith(p) for p in self._TRUSTED_PATHS)
            in_suspicious = any(p in a_lower for p in self._SUSPICIOUS_PATHS)
            bad_ext       = any(a_lower.endswith(ext) for ext in self._SUSPICIOUS_EXTS)
            is_suspicious = in_suspicious or bad_ext or not in_trusted

        return {
            "task_name":               _str(record.get("Task Name")),
            "key_name":                _str(record.get("Key Name")),
            "action":                  action or None,
            "action_arguments":        _str(record.get("Action Arguments")),
            "action_type":             action_type or None,
            "action_context":          _str(record.get("Action Context")),
            "trigger_type":            _str(record.get("Trigger Type")),
            "trigger_description":     _str(record.get("Trigger Description")),
            "enabled":                 enabled,
            "last_run_time":           _str(record.get("Last Run Time")),
            "last_successful_run_time": _str(record.get("Last Successful Run Time")),
            "working_directory":       _str(record.get("Working Directory")),
            "is_suspicious":           is_suspicious,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 200) -> dict:
        # Include all Exe-type tasks; skip pure-GUID ComHandler tasks with no task name
        # (these are almost always built-in Windows system tasks)
        interesting = [
            r for r in rows
            if r.get("action_type") == "Exe"
            or (
                r.get("action_type") == "ComHandler"
                and (r.get("task_name") or r.get("trigger_type") == "Logon")
            )
        ]
        suspicious = [r for r in interesting if r.get("is_suspicious")]
        note = (
            f"{len(rows)} total scheduled tasks; "
            f"{len(interesting)} included (all Exe-type + named/logon ComHandler); "
            f"{len(suspicious)} flagged suspicious (Exe outside Windows/ProgramFiles or script extension). "
            f"Showing first {min(len(interesting), max_rows)}."
        )
        return {
            "total_rows":   len(rows),
            "flagged_rows": len(suspicious),
            "rows":         interesting[:max_rows],
            "filter_note":  note,
        }


class HashdumpParser(BaseParser):
    def normalise(self, record: dict) -> dict | None:
        return {
            "user": _str(record.get("User") or record.get("Username")),
            "rid": _int(record.get("rid") or record.get("RID")),
            "lm_hash": _str(record.get("lmhash") or record.get("LM")),
            "nt_hash": _str(record.get("nthash") or record.get("NT")),
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/linux_bash.py

class LinuxBashParser(BaseParser):
    SUSPICIOUS_COMMANDS = (
        "curl", "wget", "nc ", "netcat", "ncat",
        "chmod +x", "python -c", "perl -e", "ruby -e",
        "base64", "xxd", "/dev/tcp", "mkfifo",
        "crontab", "iptables", "useradd", "passwd",
    )

    def normalise(self, record: dict) -> dict | None:
        cmd = _str(record.get("Command") or record.get("CommandHistory"))
        return {
            "pid": _int(record.get("PID") or record.get("Pid")),
            "process": _str(record.get("Process")),
            "command": cmd,
            "is_suspicious": bool(cmd and any(s in cmd.lower() for s in self.SUSPICIOUS_COMMANDS)),
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/linux_lsmod.py

class LinuxLsmodParser(BaseParser):
    # Subclasses may override to mark all records as hidden by definition
    _all_hidden: bool = False

    def normalise(self, record: dict) -> dict | None:
        is_hidden = self._all_hidden or _bool(record.get("Hidden") or record.get("NotInSysfs")) or False
        return {
            "offset": _hex(record.get("Offset")),
            "name": _str(record.get("Module Name") or record.get("Name")),
            "size": _int(record.get("Code Size") or record.get("Size")),
            "used_by": _str(record.get("Used by") or record.get("Load Arguments")),
            "is_hidden": is_hidden,
        }


class LinuxHiddenModuleParser(LinuxLsmodParser):
    """check_modules / hidden_modules — every emitted record is hidden by definition."""
    _all_hidden: bool = True


class LinuxModxviewParser(BaseParser):
    """
    linux.malware.modxview — cross-view of kernel modules across procfs, sysfs and memory scan.
    A module is hidden if absent from any enumeration method.
    """

    def normalise(self, record: dict) -> dict | None:
        name = _str(record.get("Name"))
        if not name:
            return None
        in_procfs = _bool(record.get("In procfs"))
        in_sysfs  = _bool(record.get("In sysfs"))
        in_scan   = _bool(record.get("In scan"))
        is_hidden = (in_procfs is False or in_sysfs is False or in_scan is False)
        return {
            "offset": _hex(record.get("Address")),
            "name": name,
            "in_procfs": in_procfs,
            "in_sysfs": in_sysfs,
            "in_scan": in_scan,
            "taints": _str(record.get("Taints")),
            "is_hidden": is_hidden,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        hidden = [r for r in rows if r.get("is_hidden")]
        note = (
            f"{len(hidden)} modules absent from one or more enumeration methods "
            f"of {len(rows)} total — hidden modules indicate LKM rootkits."
            if hidden else
            f"All {len(rows)} modules visible across procfs, sysfs and memory scan — no hidden modules."
        )
        return {"total_rows": len(rows), "flagged_rows": len(hidden), "rows": hidden[:max_rows], "filter_note": note}


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/generic.py

class GenericParser(BaseParser):
    """Pass-through parser: converts column/row format to list of dicts."""
    pass


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/psxview.py

class PsxviewParser(BaseParser):
    """
    windows.psxview — cross-view process enumeration.

    Schema:
    {
        "offset": str, "name": str, "pid": int,
        "pslist": bool|None, "psscan": bool|None, "thrdscan": bool|None,
        "pspcdid": bool|None, "csrss": bool|None, "session": bool|None,
        "deskthrd": bool|None,
        "is_hidden": bool   # True if explicitly False in any method
    }
    """
    # (output key, list of field name variants to try — newest Volatility3 first)
    _METHODS = [
        ("pslist",   ["pslist",   "PsList"]),
        ("psscan",   ["psscan",   "PsScan"]),
        ("thrdscan", ["thrdscan", "ThrdProc", "thrdproc"]),
        ("pspcdid",  ["pspcdid",  "PspCid"]),
        ("csrss",    ["csrss",    "Csrss"]),
        ("session",  ["session",  "Session"]),
        ("deskthrd", ["deskthrd", "DeskThrd"]),
    ]

    def normalise(self, record: dict) -> dict | None:
        pid = record.get("PID") or record.get("Pid")
        if not pid:
            return None

        method_values: dict[str, bool | None] = {}
        for out_key, variants in self._METHODS:
            val = None
            for v in variants:
                if v in record:
                    val = _bool(record[v])
                    break
            method_values[out_key] = val

        # is_hidden only when a method explicitly reports False (not merely absent)
        is_hidden = any(v is False for v in method_values.values())

        offset_raw = (
            record.get("Offset(Virtual)")
            or record.get("Offset(V)")
            or record.get("Offset")
        )
        return {
            "offset":    _hex(offset_raw),
            "name":      _str(record.get("ImageFileName") or record.get("Name")),
            "pid":       _int(pid),
            **method_values,
            "is_hidden": is_hidden,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        hidden = [r for r in rows if r.get("is_hidden")]
        note = (
            f"{len(hidden)} hidden processes of {len(rows)} total "
            f"(hidden = absent from one or more enumeration methods)."
        )
        return {
            "total_rows": len(rows),
            "flagged_rows": len(hidden),
            "rows": hidden[:max_rows],
            "filter_note": note,
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/svcscan.py

class SvcscanParser(BaseParser):
    """
    windows.svcscan / windows.malware.svcdiff — Windows service records.

    Schema:
    {
        "offset": str, "order": int, "pid": int,
        "start": str, "state": str, "type": str,
        "name": str, "display": str, "binary_path": str | None,
        "is_suspicious": bool
    }
    """
    _SUSPICIOUS_PATH_FRAGMENTS = (
        "\\temp\\", "\\tmp\\", "\\appdata\\", "\\users\\",
        "\\programdata\\", "%temp%", "%appdata%",
    )

    def normalise(self, record: dict) -> dict | None:
        name = _str(record.get("Name") or record.get("ServiceName"))
        binary = _str(record.get("Binary") or record.get("BinaryPath") or record.get("ImagePath"))
        binary_lower = (binary or "").lower()

        is_suspicious = any(p in binary_lower for p in self._SUSPICIOUS_PATH_FRAGMENTS)

        return {
            "offset": _hex(record.get("Offset")),
            "order": _int(record.get("Order")),
            "pid": _int(record.get("PID") or record.get("Pid")),
            "start": _str(record.get("Start")),
            "state": _str(record.get("State")),
            "type": _str(record.get("Type")),
            "name": name,
            "display": _str(record.get("Display")),
            "binary_path": binary,
            "is_suspicious": is_suspicious,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        suspicious = [r for r in rows if r.get("is_suspicious")]
        normal = [r for r in rows if not r.get("is_suspicious")]
        # Include all suspicious + sample of normal
        display = suspicious + normal[:max(0, max_rows - len(suspicious))]
        note = (
            f"{len(suspicious)} suspicious services (unusual binary paths) of {len(rows)} total. "
            f"Showing all suspicious plus {len(display) - len(suspicious)} normal services."
        )
        return {
            "total_rows": len(rows),
            "flagged_rows": len(suspicious),
            "rows": display[:max_rows],
            "filter_note": note,
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/ldrmodules.py

class LdrmodulesParser(BaseParser):
    """
    windows.malware.ldrmodules — cross-references the three PEB loader lists.

    Schema:
    {
        "pid": int, "process": str, "base": str,
        "in_load": bool, "in_init": bool, "in_mem": bool,
        "mapped_path": str | None,
        "is_hidden": bool   # True if absent from any loader list
    }
    """

    def normalise(self, record: dict) -> dict | None:
        pid = record.get("PID") or record.get("Pid")

        in_load = _bool(record.get("InLoad") or record.get("InLoadOrder"))
        in_init = _bool(record.get("InInit") or record.get("InInitializationOrder"))
        in_mem  = _bool(record.get("InMem")  or record.get("InMemoryOrder"))

        # Process executable legitimately has False for InInit — not suspicious
        mapped = _str(record.get("MappedPath") or record.get("Path"))
        is_hidden = (in_load is False or in_mem is False)

        return {
            "pid": _int(pid),
            "process": _str(record.get("Process")),
            "base": _hex(record.get("Base")),
            "in_load": in_load,
            "in_init": in_init,
            "in_mem": in_mem,
            "mapped_path": mapped,
            "is_hidden": is_hidden,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        hidden = [r for r in rows if r.get("is_hidden")]
        note = (
            f"{len(hidden)} DLLs unlinked from PEB loader lists of {len(rows)} total."
        )
        return {
            "total_rows": len(rows),
            "flagged_rows": len(hidden),
            "rows": hidden[:max_rows],
            "filter_note": note,
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/kernel_hook.py

class UnloadedModulesParser(BaseParser):
    """
    windows.unloadedmodules

    Records the last ~50 kernel modules that were unloaded (Windows keeps a
    circular buffer). Useful for spotting drivers that loaded briefly — a
    common malware self-cleanup tactic.

    Schema: name, start_address, end_address, size, unload_time
    """

    def normalise(self, record: dict) -> dict | None:
        name = _str(record.get("Name") or record.get("BaseDllName"))
        if not name:
            return None

        start = record.get("StartAddress")
        end   = record.get("EndAddress")
        size  = (int(end) - int(start)) if (start and end) else None

        # 1601-01-01 is the Windows epoch default — means no real timestamp
        unload_time = _str(record.get("Time"))
        if unload_time and unload_time.startswith("1601-01-01"):
            unload_time = None

        return {
            "name":          name,
            "start_address": _hex(start),
            "end_address":   _hex(end),
            "size":          size,
            "unload_time":   unload_time,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 200) -> dict:
        note = (
            f"{len(rows)} recently unloaded kernel modules "
            f"(Windows circular buffer, last ~50 entries). All shown."
        )
        return {
            "total_rows":   len(rows),
            "flagged_rows": 0,
            "rows":         rows[:max_rows],
            "filter_note":  note,
        }


class ModscanParser(BaseParser):
    """
    windows.modscan

    Pool-tag scan for loaded kernel modules. Complements windows.modules
    (which walks the PsLoadedModuleList) by finding modules that have been
    unlinked from that list — a classic rootkit hiding technique.

    Schema: offset, base_address, name, path, size, is_suspicious

    is_suspicious = module path is outside \\SystemRoot\\ / \\Windows\\ /
                    \\Program Files\\ (the standard kernel-mode load locations).
    """
    _TRUSTED_PATH_PREFIXES = (
        "\\systemroot\\",
        "\\windows\\",
        "\\program files\\",
        "\\program files (x86)\\",
        # Virtualisation / hypervisor paths seen in some environments
        "\\device\\harddisk",
    )

    def normalise(self, record: dict) -> dict | None:
        name = _str(record.get("Name") or record.get("BaseDllName"))
        if not name:
            return None

        path     = _str(record.get("Path") or record.get("FullDllName"))
        path_low = path.lower() if path else None

        if path_low:
            trusted = any(path_low.startswith(p) for p in self._TRUSTED_PATH_PREFIXES)
        else:
            trusted = False  # no path → can't verify → suspicious

        return {
            "offset":        _hex(record.get("Offset")),
            "base_address":  _hex(record.get("Base") or record.get("DllBase")),
            "name":          name,
            "path":          path,
            "size":          _int(record.get("Size")),
            "is_suspicious": not trusted,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        suspicious = [r for r in rows if r.get("is_suspicious")]
        note = (
            f"{len(rows)} kernel modules found by pool scan; "
            f"{len(suspicious)} flagged suspicious "
            f"(path outside \\SystemRoot\\ / \\Windows\\ / \\Program Files\\). "
            f"Suspicious entries shown first."
        )
        combined = suspicious + [r for r in rows if not r.get("is_suspicious")]
        return {
            "total_rows":   len(rows),
            "flagged_rows": len(suspicious),
            "rows":         combined[:max_rows],
            "filter_note":  note,
        }


class MbrscanParser(BaseParser):
    """
    windows.mbrscan

    Parent rows = one MBR-like structure found in memory.
    Children    = individual partition table entries.

    Schema: physical_offset, disk_signature, bootcode_md5, full_mbr_md5,
            disasm_preview, partitions (list), is_suspicious

    Suspicious indicators:
    - physical_offset > 0  (real MBR lives at sector 0; others are hidden copies)
    - partition types that are undefined/corrupt
    """
    _LEGIT_PARTITION_TYPES = frozenset({
        "ntfs", "ntfs / exfat", "exfat",
        "fat12", "fat16", "fat32", "fat32 (lba)",
        "extended", "extended (lba)", "extended with lba",
        "efi system partition", "microsoft basic data", "microsoft reserved",
        "linux", "linux swap", "linux extended", "linux lvm",
        "windows recovery environment", "windows re",
        "bios boot partition", "empty",
    })

    def parse(self, data: dict | list) -> list[dict]:
        rows: list = data if isinstance(data, list) else data.get("rows", [])
        records = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            children = row.get("__children") or []
            partitions = []
            for child in children:
                if not isinstance(child, dict) or child.get("PartitionIndex") is None:
                    continue
                partitions.append({
                    "index":       _int(child.get("PartitionIndex")),
                    "type":        _str(child.get("PartitionType")),
                    "bootable":    _bool(child.get("Bootable")),
                    "sector_size": _int(child.get("SectorInSize")),
                })
            clean = {k: _clean(v) for k, v in row.items() if not k.startswith("__")}
            clean["_partitions"] = partitions
            rec = self.normalise(clean)
            if rec:
                records.append(rec)
        return records

    def normalise(self, record: dict) -> dict | None:
        offset      = _int(record.get("Potential MBR at Physical Offset"))
        partitions  = record.get("_partitions", [])

        nonzero_offset  = offset is not None and offset > 0
        bad_part_types  = [
            p for p in partitions
            if p.get("type") and p["type"].lower() not in self._LEGIT_PARTITION_TYPES
        ]
        is_suspicious = nonzero_offset or bool(bad_part_types)

        # Disasm is huge — keep only first 10 non-empty lines as a preview
        disasm_raw    = _str(record.get("Disasm")) or ""
        disasm_lines  = [l.strip() for l in disasm_raw.splitlines() if l.strip()]
        disasm_preview = "\n".join(disasm_lines[:10]) or None

        return {
            "physical_offset": offset,
            "disk_signature":  _str(record.get("Disk Signature")),
            "bootcode_md5":    _str(record.get("Bootcode MD5")),
            "full_mbr_md5":    _str(record.get("Full MBR MD5")),
            "disasm_preview":  disasm_preview,
            "partitions":      partitions,
            "is_suspicious":   is_suspicious,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 50) -> dict:
        suspicious = [r for r in rows if r.get("is_suspicious")]
        note = (
            f"{len(rows)} MBR-like structures found in memory; "
            f"{len(suspicious)} flagged suspicious "
            f"(non-zero physical offset or undefined partition types)."
        )
        combined = suspicious + [r for r in rows if not r.get("is_suspicious")]
        return {
            "total_rows":   len(rows),
            "flagged_rows": len(suspicious),
            "rows":         combined[:max_rows],
            "filter_note":  note,
        }


class DriverscanParser(BaseParser):
    """
    windows.driverscan

    Schema: offset, name, driver_name, service_key, start_address, size,
            is_suspicious

    Drivers with Size == 0 are virtual/built-in driver objects (PnpManager,
    SoftwareDevice, etc.) — not real loaded images; flagged separately via
    size_zero. Drivers with Size > 0 and not in the known Windows driver set
    are flagged is_suspicious.
    """
    _KNOWN_DRIVERS = frozenset({
        # Core kernel / HAL
        "acpi", "acpi_hal", "hal", "pnpmanager", "softwaredevice", "deviceapi",
        "wmixwdm", "msseccore", "prm",
        # Storage
        "storahci", "storport", "atapi", "disk", "partmgr", "volmgr", "volsnap",
        "fvevol", "rdyboost", "classpnp", "cdrom", "mountmgr",
        "ntfs", "refs", "fat", "exfat", "cdfs", "udfs", "fltmgr",
        "acpiex",
        # WDF / PnP
        "wdf01000", "wdfldr", "wdmound",
        # Security / crypto
        "cng", "ksecdd", "ksecpkg", "ci", "peauth", "wtd", "appid",
        "wdfilter", "wdboot", "wdnisdrv", "hvsifltr", "hvsi",
        # Networking
        "tcpip", "tcpip6", "ndis", "netio", "tdx", "afd", "pacer",
        "netbios", "rdbss", "mrxsmb", "mrxsmb20",
        "nsiproxy", "ipnat", "ipsec",
        # USB
        "usbhub", "usbhub3", "usbccgp", "usbehci", "usbxhci", "usbport",
        "usbstor", "usbcir", "hidusbfx2",
        # HID / input
        "hidclass", "hidparse", "kbdhid", "mouhid", "kbdclass", "mouclass",
        # Display / audio
        "dxgkrnl", "dxgmms1", "dxgmms2", "basicdisplay", "basicrender",
        "hdaudbus", "portcls", "ks", "mmcss",
        # Power / ACPI helpers
        "battc", "compbatt", "atapi",
        "iorate", "ahcache",
        # VM / hypervisor paravirt drivers
        "vmbus", "storvsc", "netvsc", "vid", "hyperkbd",
        "vm3dmp", "vm3dservice", "vmrawdsk",
        "hypervideo", "hvservice",
        # Misc Windows components
        "pci", "pciide", "pciidex", "isapnp", "msisadrv",
        "mssmbios", "kdnic", "nhi0",
        "sysenv", "mup", "fileinfo", "fs_rec",
        "null", "beep", "vga", "vgasave", "bootvid",
        "ndistapi", "rasacd", "rasl2tp", "raspppoe", "raspptp",
        # Security / integrity
        "codeintegrity",
    })

    def normalise(self, record: dict) -> dict | None:
        name = _str(record.get("Name"))
        if not name:
            return None
        driver_name = _str(record.get("Driver Name")) or name.lstrip("\\").split("\\")[-1]
        dn_lower    = driver_name.lower()
        size        = _int(record.get("Size")) or 0
        is_suspicious = (
            size > 0
            and dn_lower not in self._KNOWN_DRIVERS
        )
        return {
            "offset":         _hex(record.get("Offset")),
            "name":           name,
            "driver_name":    driver_name,
            "service_key":    _str(record.get("Service Key")),
            "start_address":  _hex(record.get("Start")),
            "size":           size,
            "is_suspicious":  is_suspicious,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        # Split: real loaded images (size > 0) vs virtual driver objects (size == 0)
        real      = [r for r in rows if r.get("size", 0) > 0]
        suspicious = [r for r in real if r.get("is_suspicious")]
        note = (
            f"{len(rows)} driver objects total; {len(real)} with loaded images; "
            f"{len(suspicious)} flagged suspicious (not in known Windows driver set). "
            f"Zero-size built-in driver objects omitted."
        )
        combined = suspicious + [r for r in real if not r.get("is_suspicious")]
        return {
            "total_rows":   len(rows),
            "flagged_rows": len(suspicious),
            "rows":         combined[:max_rows],
            "filter_note":  note,
        }


class DriverIrpParser(BaseParser):
    """
    windows.driverirp

    Schema: driver_offset, driver_name, irp, handler_address, module,
            symbol, is_hooked

    is_hooked = Module is not None AND is not a known kernel/filter module.
    Module being None means the handler could not be resolved — recorded but
    not flagged (symbol resolution failures are common without full PDBs).
    """
    # Modules that legitimately appear in IRP dispatch tables (filter drivers,
    # WDF framework, class/port driver stacks).
    _LEGIT_MODULES = frozenset({
        "ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe",
        "win32k.sys", "hal.dll", "__kernel__",
        "fltmgr.sys", "fltmgr",
        "wdf01000.sys", "wdf01000",
        "wdfldr.sys",
        "classpnp.sys", "classpnp",
        "storport.sys", "storport",
        "disk.sys", "disk",
        "ndis.sys", "ndis",
        "pnpmgr",
        "acpi.sys", "acpi",
    })

    def normalise(self, record: dict) -> dict | None:
        module = _str(record.get("Module") or record.get("Owner"))
        mod_lower = module.lower().strip("\\") if module else None

        if mod_lower is not None:
            is_hooked = (
                mod_lower not in self._LEGIT_MODULES
                and not mod_lower.startswith("nt")
            )
        else:
            is_hooked = False  # unresolved — can't determine

        return {
            "driver_offset":  _hex(record.get("Offset")),
            "driver_name":    _str(record.get("Driver Name")),
            "irp":            _str(record.get("IRP")),
            "handler_address": _hex(record.get("Address")),
            "module":         module,
            "symbol":         _str(record.get("Symbol")),
            "is_hooked":      is_hooked,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        hooked = [r for r in rows if r.get("is_hooked")]
        if hooked:
            note = (
                f"{len(hooked)} hooked IRP handlers of {len(rows)} total "
                f"(handler module differs from driver and is not a known filter/class driver)."
            )
            return {
                "total_rows":   len(rows),
                "flagged_rows": len(hooked),
                "rows":         hooked[:max_rows],
                "filter_note":  note,
            }
        # No hooks — collapse into a per-driver summary to avoid flooding the AI
        # with 28 IRP entries × every driver.
        from collections import defaultdict
        by_driver: dict[str, dict] = {}
        for r in rows:
            key = r.get("driver_offset") or "unknown"
            if key not in by_driver:
                by_driver[key] = {
                    "driver_offset": r.get("driver_offset"),
                    "driver_name":   r.get("driver_name"),
                    "irp_count":     0,
                    "unresolved":    0,
                }
            by_driver[key]["irp_count"] += 1
            if r.get("module") is None:
                by_driver[key]["unresolved"] += 1
        summary = list(by_driver.values())
        note = (
            f"No hooked IRP handlers detected across {len(rows)} entries "
            f"({len(summary)} drivers). Summarised by driver — "
            f"'unresolved' = IRP handlers that could not be resolved to a module."
        )
        return {
            "total_rows":   len(rows),
            "flagged_rows": 0,
            "rows":         summary[:max_rows],
            "filter_note":  note,
        }


class DevicetreeParser(BaseParser):
    """
    windows.devicetree

    Three-level tree: DRV (driver object) → DEV (device) → ATT (attached device).
    Flattened into one record per DEV entry, with attached driver names collected
    from ATT children. DRV entries with no devices are emitted as stub records so
    that unnamed/unknown driver objects are still visible to the AI.

    Schema: driver_name, driver_offset, device_name, device_type,
            attached_drivers, is_suspicious
    """
    _KNOWN_DRIVERS = frozenset({
        "pnpmanager", "acpi", "pci", "isapnp",
        "msisadrv", "ftdisk", "partmgr", "volmgr", "fvevol",
        "rdyboost", "mup", "fileinfo",
        "ntfs", "refs", "fat", "exfat", "cdfs", "udfs",
        "fltmgr", "wdfilter",
        "tcpip", "tdx", "ndis", "netbios", "afd",
        "disk", "cdrom", "atapi", "storport", "classpnp",
        "usbhub", "usbhub3", "usbccgp", "usbehci", "usbxhci",
        "monitor", "dxgkrnl", "dxgmms1",
        "rdpbus", "rdpdr", "rdpvideominiport",
        "vmbus", "storvsc", "netvsc", "hyperkbd",
        "vm3dmp", "vmhgfs",
        "nhi0", "kdnic",
    })

    def parse(self, data: dict | list) -> list[dict]:
        rows: list = data if isinstance(data, list) else data.get("rows", [])
        records = []
        for drv in rows:
            if not isinstance(drv, dict) or drv.get("Type") != "DRV":
                continue
            driver_name   = _str(drv.get("DriverName"))
            driver_offset = _hex(drv.get("Offset"))
            dev_children  = [c for c in (drv.get("__children") or [])
                              if isinstance(c, dict) and c.get("Type") == "DEV"]
            if not dev_children:
                # Emit a stub so unnamed driver objects aren't silently dropped
                rec = self.normalise({
                    "driver_name":    driver_name,
                    "driver_offset":  driver_offset,
                    "device_name":    None,
                    "device_type":    None,
                    "attached_drivers": [],
                })
                if rec:
                    records.append(rec)
                continue
            for dev in dev_children:
                att_children = [c for c in (dev.get("__children") or [])
                                if isinstance(c, dict) and c.get("Type") == "ATT"]
                attached = [
                    _str(a.get("DriverNameOfAttDevice"))
                    for a in att_children
                    if _str(a.get("DriverNameOfAttDevice"))
                ]
                rec = self.normalise({
                    "driver_name":      driver_name,
                    "driver_offset":    driver_offset,
                    "device_name":      _str(dev.get("DeviceName")),
                    "device_type":      _str(dev.get("DeviceType")),
                    "attached_drivers": attached,
                })
                if rec:
                    records.append(rec)
        return records

    def normalise(self, record: dict) -> dict | None:
        driver_name = record.get("driver_name")
        dn_lower    = driver_name.lower().lstrip("\\").split("\\")[-1] if driver_name else None

        unknown_driver = driver_name is None
        unknown_module = dn_lower is not None and dn_lower not in self._KNOWN_DRIVERS

        is_suspicious = unknown_driver or unknown_module

        return {
            "driver_name":      driver_name,
            "driver_offset":    record.get("driver_offset"),
            "device_name":      record.get("device_name"),
            "device_type":      record.get("device_type"),
            "attached_drivers": record.get("attached_drivers", []),
            "is_suspicious":    is_suspicious,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        suspicious = [r for r in rows if r.get("is_suspicious")]
        note = (
            f"{len(rows)} device entries across all driver objects; "
            f"{len(suspicious)} flagged suspicious "
            f"(null or unrecognised driver name). Suspicious entries shown first."
        )
        combined = suspicious + [r for r in rows if not r.get("is_suspicious")]
        return {
            "total_rows":   len(rows),
            "flagged_rows": len(suspicious),
            "rows":         combined[:max_rows],
            "filter_note":  note,
        }


class CallbacksParser(BaseParser):
    """
    windows.callbacks

    Schema: callback_address, type, module, symbol, detail, is_suspicious

    is_suspicious = module is None (unresolved handler — strong rootkit signal)
                  OR module is not in the known Windows kernel/driver set
    """
    _TRUSTED_MODULES = frozenset({
        # Core kernel
        "ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe",
        "hal.dll", "win32k.sys",
        # Common Windows kernel drivers that legitimately register callbacks
        "cng", "ci", "ksecdd", "peauth", "wtd", "appid",
        "tcpip", "ndis", "tdx",
        "dxgkrnl", "dxgmms1", "dxgmms2",
        "fltmgr.sys", "fltmgr",
        "wdfilter", "wdfilter.sys",   # Windows Defender
        "mmcss",                       # Multimedia Class Scheduler
        "iorate",                      # I/O rate limiter
        "ahcache",                     # Application compatibility cache
        "acpi", "acpi.sys",
        "pnpmgr",
        "storport", "storport.sys",
        "classpnp", "classpnp.sys",
        "disk", "disk.sys",
        "vm3dmp",                      # VMware 3D driver (common in VMs)
        "wdf01000.sys", "wdf01000",
    })

    def normalise(self, record: dict) -> dict | None:
        addr_raw = record.get("Callback") or record.get("Address") or record.get("Offset")
        if addr_raw is None:
            return None

        module = _str(record.get("Module") or record.get("Owner"))
        mod_lower = module.lower().strip("\\") if module else None

        is_suspicious = (
            mod_lower is None
            or (mod_lower not in self._TRUSTED_MODULES and not mod_lower.startswith("nt"))
        )

        return {
            "callback_address": _hex(addr_raw),
            "type":             _str(record.get("Type")),
            "module":           module,
            "symbol":           _str(record.get("Symbol")),
            "detail":           _str(record.get("Detail")),
            "is_suspicious":    is_suspicious,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        suspicious = [r for r in rows if r.get("is_suspicious")]
        note = (
            f"{len(rows)} kernel callbacks; "
            f"{len(suspicious)} flagged suspicious "
            f"(unresolved module or module not in known Windows driver set)."
            if suspicious else
            f"{len(rows)} kernel callbacks — all registered by known Windows modules."
        )
        return {
            "total_rows":   len(rows),
            "flagged_rows": len(suspicious),
            "rows":         suspicious if suspicious else rows[:max_rows],
            "filter_note":  note,
        }


class KernelHookParser(BaseParser):
    """
    Generic parser for kernel hook-detection plugins:
      windows.ssdt, windows.callbacks, windows.driverirp,
      linux.malware.check_syscall, linux.malware.check_idt,
      linux.malware.check_afinfo, linux.malware.keyboard_notifiers,
      linux.tty_check, linux.tracing.ftrace,
      linux.malware.netfilter, mac.check_syscall, mac.check_trap_table,
      mac.check_sysctl, mac.socket_filters, mac.kauth_listeners

    Detects entries whose handler address falls outside the kernel text
    section (i.e., inside a loadable module or unknown memory).

    Schema:
    {
        "index": str | None, "symbol": str | None,
        "address": str, "module": str | None,
        "is_hooked": bool
    }
    """
    # Modules considered part of the legitimate kernel or a trusted Microsoft
    # infrastructure layer that legitimately appears in hook/dispatch tables.
    _KERNEL_MODULES = frozenset({
        # Windows kernel images
        "ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe",
        "win32k.sys", "hal.dll",
        # Linux / macOS kernel images
        "kernel", "vmlinux", "mach_kernel",
        # Volatility3 uses "__kernel__" for handlers that resolve to the core
        # kernel image itself (e.g. asm_exc_divide_error, asm_exc_page_fault).
        # These are always legitimate — a rootkit cannot hide inside __kernel__.
        "__kernel__",
        # ── Windows IRP / callback infrastructure (driverirp false-positives) ──
        # WDF: every driver built on Windows Driver Framework routes its IRP
        # dispatch through Wdf01000.sys. This is architectural, not hooking.
        "wdf01000.sys",
        "wdfldr.sys",
        # Storage and class driver stack — CLASSPNP acts as a dispatch proxy
        # for disk, CD-ROM, and tape class drivers.
        "classpnp.sys",
        "storport.sys",
        "disk.sys",
        # File-system filter manager — FltMgr.sys inserts itself into all
        # IRP paths for minifilter drivers (AV, backup, encryption layers).
        "fltmgr.sys",
        # NDIS — network driver interface standard; handles IRP for NICs.
        "ndis.sys",
        # PnP / power manager callbacks inserted by the OS
        "pnpmgr.sys",
        "acpi.sys",
    })

    def normalise(self, record: dict) -> dict | None:
        _addr_candidates = [
            record.get("Handler Address"),  # linux.malware.check_syscall / check_idt
            record.get("Handler"),
            record.get("Address"),
            record.get("Offset"),
            record.get("FunctionAddress"),
            record.get("CallbackRoutine"),
        ]
        address = _hex(next((v for v in _addr_candidates if v is not None), None))
        if not address:
            return None

        module = _str(
            record.get("Module")
            or record.get("Owner")
            or record.get("Symbol")
        )
        symbol = _str(
            record.get("Handler Symbol")    # linux.malware.check_syscall / check_idt
            or record.get("Symbol")
            or record.get("Name")
            or record.get("SyscallName")
            or record.get("Type")
        )

        # Prefer Volatility's own "Is Hooked" verdict when present (e.g. linux.malware.netfilter).
        # Fall back to heuristic: handler outside known kernel modules.
        vol_hooked = record.get("Is Hooked")
        if vol_hooked is not None:
            is_hooked = str(vol_hooked).strip().lower() in ("true", "1", "yes")
        else:
            is_hooked = False
            if module:
                mod_lower = module.lower().strip("\\")
                is_hooked = mod_lower not in self._KERNEL_MODULES and not mod_lower.startswith("nt")

        return {
            "index": _str(record.get("Index") or record.get("Number") or record.get("Syscall")),
            "hook": _str(record.get("Hook")),
            "proto": _str(record.get("Proto")),
            "net_ns": _int(record.get("Net NS")),
            "symbol": symbol,
            "address": address,
            "module": module,
            "is_hooked": is_hooked,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        hooked = [r for r in rows if r.get("is_hooked")]
        note = (
            f"{len(hooked)} hooked entries of {len(rows)} total syscall/callback/hook table entries."
            if hooked else
            f"No hooks detected in {len(rows)} entries — all handlers resolve to known kernel modules."
        )
        return {
            "total_rows": len(rows),
            "flagged_rows": len(hooked),
            "rows": hooked[:max_rows],
            "filter_note": note,
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/lsof.py

class LsofParser(BaseParser):
    """
    linux.lsof / mac.lsof — open file descriptors per process.

    Schema:
    {
        "pid": int, "process": str, "fd": str,
        "type": str | None, "path": str | None,
        "is_sensitive": bool
    }
    """
    _SENSITIVE_PATHS = (
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        "id_rsa", "id_ecdsa", "id_ed25519", "authorized_keys",
        "/dev/mem", "/dev/kmem", "/proc/kcore",
        "login data", "cookies", "logins.json",  # browser credential stores
        "/private/var/db/",  # macOS TCC / authorization
    )

    def normalise(self, record: dict) -> dict | None:
        pid = record.get("PID") or record.get("Pid")
        path = _str(record.get("Path") or record.get("Name") or record.get("File"))
        path_lower = (path or "").lower()

        is_sensitive = any(s in path_lower for s in self._SENSITIVE_PATHS)

        return {
            "pid": _int(pid),
            "process": _str(record.get("Process") or record.get("Comm")),
            "fd": _str(record.get("FD") or record.get("FileDescriptor")),
            "type": _str(record.get("Type")),
            "path": path,
            "is_sensitive": is_sensitive,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        sensitive = [r for r in rows if r.get("is_sensitive")]
        other = [r for r in rows if not r.get("is_sensitive")]
        display = sensitive + other[:max(0, max_rows - len(sensitive))]
        note = (
            f"{len(sensitive)} sensitive file descriptors (shadow/keys/raw-device) of {len(rows)} total. "
            f"Showing all sensitive plus {len(display) - len(sensitive)} others."
        )
        return {
            "total_rows": len(rows),
            "flagged_rows": len(sensitive),
            "rows": display[:max_rows],
            "filter_note": note,
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/envars.py

class EnvarsParser(BaseParser):
    """
    linux.envars / mac.envars / windows.envars — process environment variables.

    Schema:
    {
        "pid": int, "process": str,
        "key": str, "value": str | None,
        "ld_preload": str | None,        # non-None when key is LD_PRELOAD / DYLD_INSERT_LIBRARIES
        "is_suspicious": bool
    }
    """
    _SUSPICIOUS_KEYS = frozenset({
        "LD_PRELOAD", "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
    })
    _SUSPICIOUS_VALUE_FRAGMENTS = (
        "/tmp/", "/dev/shm/", "/var/tmp/",
        "base64", "eval", "exec(",
    )

    def normalise(self, record: dict) -> dict | None:
        key   = _str(record.get("KEY") or record.get("Variable") or record.get("Key") or record.get("Name"))
        value = _str(record.get("VALUE") or record.get("Value") or record.get("Data"))
        if not key:
            return None

        key_upper = key.upper()
        is_preload_key = key_upper in self._SUSPICIOUS_KEYS
        value_lower = (value or "").lower()
        is_suspicious = is_preload_key or any(f in value_lower for f in self._SUSPICIOUS_VALUE_FRAGMENTS)

        return {
            "pid": _int(record.get("PID") or record.get("Pid")),
            "process": _str(record.get("COMM") or record.get("Process") or record.get("Comm")),
            "key": key,
            "value": value,
            "ld_preload": value if is_preload_key else None,
            "is_suspicious": is_suspicious,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        suspicious = [r for r in rows if r.get("is_suspicious")]
        note = (
            f"{len(suspicious)} suspicious environment variables (LD_PRELOAD/DYLD_INSERT/temp-path values) "
            f"of {len(rows)} total env var entries."
        )
        return {
            "total_rows": len(rows),
            "flagged_rows": len(suspicious),
            "rows": suspicious[:max_rows],
            "filter_note": note,
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/mem_maps.py

class MemMapsParser(BaseParser):
    """
    linux.proc.Maps / mac.proc_maps — per-process memory map regions.

    Schema:
    {
        "pid": int, "process": str,
        "start": str, "end": str, "size": int | None,
        "permissions": str | None,
        "file_path": str | None,
        "is_rwx": bool,
        "is_anonymous": bool,
        "is_deleted": bool
    }
    """

    def normalise(self, record: dict) -> dict | None:
        pid = record.get("PID") or record.get("Pid")
        perms = _str(
            record.get("Flags")        # linux.proc.Maps
            or record.get("Permissions") or record.get("Protection")
            or record.get("Prot") or record.get("VmFlags")
        )
        path = _str(record.get("File Path") or record.get("File") or record.get("Path") or record.get("MappedFile"))

        is_rwx      = bool(perms and "r" in perms and "w" in perms and "x" in perms)
        is_anonymous = not path or path in ("[anon]", "[heap]", "[stack]", "")
        is_deleted   = bool(path and "(deleted)" in path.lower())

        return {
            "pid": _int(pid),
            "process": _str(record.get("Process") or record.get("Comm")),
            "start": _hex(record.get("Start") or record.get("StartVPN")),
            "end": _hex(record.get("End") or record.get("EndVPN")),
            "size": _int(record.get("Size")),
            "permissions": perms,
            "file_path": path,
            "is_rwx": is_rwx,
            "is_anonymous": is_anonymous,
            "is_deleted": is_deleted,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        suspicious = [r for r in rows if r.get("is_rwx") or (r.get("is_anonymous") and r.get("permissions") and "x" in (r.get("permissions") or ""))]
        note = (
            f"{len(suspicious)} suspicious memory regions (RWX or anonymous+executable) "
            f"of {len(rows)} total memory map entries."
        )
        return {
            "total_rows": len(rows),
            "flagged_rows": len(suspicious),
            "rows": suspicious[:max_rows],
            "filter_note": note,
        }


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/syscall_direct.py

class SyscallDirectParser(BaseParser):
    """
    windows.malware.direct_system_calls / windows.malware.indirect_system_calls

    These plugins output every process's syscall invocations. Known-legitimate
    processes (browsers, JVMs, .NET, security products) are filtered out.

    Schema: { "pid": int, "process": str, "syscall": str, "address": str }
    """
    # Processes known to legitimately use direct syscalls
    _LEGITIMATE_PROCESSES = frozenset({
        # Browsers
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
        "iexplore.exe", "microsoftedgecp.exe",
        # JVM / runtimes
        "java.exe", "javaw.exe", "node.exe", "python.exe", "python3.exe",
        "ruby.exe", "perl.exe",
        # .NET
        "dotnet.exe", "mscorsvw.exe", "ngentask.exe",
        # Windows security / AV
        "msmpeng.exe", "mrt.exe", "mssenses.exe", "securityhealthservice.exe",
        "senseir.exe", "nissrv.exe", "mpcmdrun.exe",
        # Windows system processes known to use direct syscalls
        "lsass.exe", "csrss.exe", "smss.exe",
        # Virtualisation / sandbox agents
        "vmtoolsd.exe", "vboxservice.exe", "vboxtray.exe",
    })

    def normalise(self, record: dict) -> dict | None:
        import re as _re
        pid = record.get("PID") or record.get("Pid")
        process = _str(record.get("Process") or record.get("ImageFileName"))
        disasm = _str(record.get("Disasm") or record.get("Disassembly") or "")
        # Extract syscall number from disasm: "mov eax, 0x55" → "0x55"
        m = _re.search(r"mov eax,\s*(0x[0-9a-fA-F]+|\d+)", disasm)
        syscall_num = m.group(1) if m else ""
        syscall = _str(record.get("Syscall") or record.get("SyscallName") or record.get("Name") or syscall_num)
        return {
            "pid": _int(pid),
            "process": process,
            "syscall": syscall,
            "address": _hex(record.get("Address") or record.get("Handler")),
            "disasm": disasm,
        }

    def filter_for_ai(self, rows: list[dict], max_rows: int = 300) -> dict:
        unexpected = [
            r for r in rows
            if (r.get("process") or "").lower() not in self._LEGITIMATE_PROCESSES
        ]
        note = (
            f"{len(unexpected)} unexpected processes using direct syscalls "
            f"of {len(rows)} total invocations "
            f"(filtered out known-legitimate: browsers, JVM, .NET, AV). "
            f"Showing first {min(len(unexpected), max_rows)}."
        )
        return {
            "total_rows": len(rows),
            "flagged_rows": len(unexpected),
            "rows": unexpected[:max_rows],
            "filter_note": note,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Type coercion helpers

def _int(v: Any) -> int | None:
    try:
        return int(v) if v is not None else None
    except (ValueError, TypeError):
        return None


def _str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s if s and s not in ("-", "N/A", "None") else None


def _hex(v: Any) -> str | None:
    if v is None:
        return None
    try:
        return hex(int(v)) if isinstance(v, int) else str(v)
    except (ValueError, TypeError):
        return str(v)


def _bool(v: Any) -> bool | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    return str(v).lower() in ("true", "1", "yes")
