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
            "offset": _hex(record.get("Offset(V)") or record.get("Offset")),
            "threads": _int(record.get("Threads") or record.get("ActiveThreads")),
            "handles": _int(record.get("Handles")),
            "session_id": _int(record.get("SessionId")),
            "wow64": _bool(record.get("Wow64")),
            "create_time": _str(record.get("CreateTime")),
            "exit_time": _str(record.get("ExitTime")),
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

    # VAD protection flags that indicate suspicious executable memory
    SUSPICIOUS_PROTECTIONS = {
        "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",
        "PAGE_EXECUTE_READ_WRITE",  # non-standard variant
    }

    def normalise(self, record: dict) -> dict | None:
        protection = _str(record.get("Protection") or record.get("Vad.Protection"))
        
        # Skip non-suspicious regions (e.g. PAGE_EXECUTE_READ is normal)
        if protection and protection not in self.SUSPICIOUS_PROTECTIONS:
            # Still include if there's a PE header signature
            disasm = _str(record.get("Disassembly"))
            hexdump = _str(record.get("Hexdump"))
            has_pe = bool(hexdump and ("4d 5a" in hexdump.lower() or "MZ" in (hexdump or "")))
            if not has_pe:
                return None

        disasm = _str(record.get("Disassembly"))
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
        local  = _str(record.get("LocalAddr") or record.get("Laddr"))
        remote = _str(record.get("ForeignAddr") or record.get("FAddr") or record.get("Raddr"))
        proto  = _str(record.get("Proto") or record.get("Protocol"))

        local_addr, local_port = _split_addr(local)
        remote_addr, remote_port = _split_addr(remote)

        is_external = remote_addr and not any(
            remote_addr.startswith(p) for p in self.PRIVATE_RANGES
        )

        return {
            "pid": _int(record.get("PID") or record.get("Pid")),
            "process": _str(record.get("Owner") or record.get("Process")),
            "protocol": proto,
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "state": _str(record.get("State")),
            "create_time": _str(record.get("Created") or record.get("CreateTime")),
            "is_external": is_external,
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
# backend/core/plugins/parsers/modules.py

class ModulesParser(BaseParser):
    """
    Normalise windows.modules / windows.driverscan output.
    
    {
        "offset": str, "base": str, "size": int,
        "name": str, "path": str | None,
        "file_output": str | None
    }
    """

    def normalise(self, record: dict) -> dict | None:
        name = _str(record.get("Name") or record.get("BaseDllName"))
        if not name:
            return None
        return {
            "offset": _hex(record.get("Offset") or record.get("DriverOffset")),
            "base": _hex(record.get("Base") or record.get("DllBase")),
            "size": _int(record.get("Size")),
            "name": name,
            "path": _str(record.get("File output") or record.get("FullDllName")),
            "service_name": _str(record.get("ServiceName")),
        }


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
    if not cmdline:
        return False
    lower = cmdline.lower()
    indicators = [
        "-enc ", "-encodedcommand", "frombase64string",
        "invoke-expression", "iex(", "invoke-webrequest",
        "downloadstring", "hidden", "-w hidden", "-windowstyle hidden",
    ]
    return any(ind in lower for ind in indicators)


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
        "Global\\MsWinZonesCacheCounterMutexA",  # KINS/ZeuS
        "ZupdService", "_AVIRA_", "IESQMMUTEX",
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
    SUSPICIOUS_PATHS = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "\\recycler\\")

    def normalise(self, record: dict) -> dict | None:
        name = _str(record.get("Name") or record.get("FileName"))
        name_lower = (name or "").lower()

        import os
        ext = os.path.splitext(name_lower)[1] if name_lower else ""
        is_suspicious_ext = ext in self.SUSPICIOUS_EXTENSIONS
        is_suspicious_path = any(p in name_lower for p in self.SUSPICIOUS_PATHS)

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
    def normalise(self, record: dict) -> dict | None:
        return {
            "offset": _hex(record.get("Offset")),
            "name": _str(record.get("Name")),
            "size": _int(record.get("Size")),
            "used_by": _str(record.get("Used by")),
            "is_hidden": _bool(record.get("Hidden") or record.get("NotInSysfs")),
        }


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
        "pslist": bool, "psscan": bool, "thrdproc": bool,
        "pspcdid": bool, "csrss": bool, "session": bool, "deskthrd": bool,
        "is_hidden": bool   # True if absent from any method
    }
    """
    # Column names Volatility3 emits for each enumeration source
    _METHOD_COLS = ("PsList", "PsScan", "ThrdProc", "PspCid", "Csrss", "Session", "DeskThrd")

    def normalise(self, record: dict) -> dict | None:
        pid = record.get("PID") or record.get("Pid")
        if not pid:
            return None

        method_values = {col: _bool(record.get(col)) for col in self._METHOD_COLS}
        is_hidden = any(v is False for v in method_values.values())

        return {
            "offset": _hex(record.get("Offset(V)") or record.get("Offset")),
            "name": _str(record.get("ImageFileName") or record.get("Name")),
            "pid": _int(pid),
            **{col.lower(): v for col, v in method_values.items()},
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
        address = _hex(
            record.get("Handler")
            or record.get("Address")
            or record.get("Offset")
            or record.get("FunctionAddress")
            or record.get("CallbackRoutine")
        )
        if not address:
            return None

        module = _str(
            record.get("Module")
            or record.get("Owner")
            or record.get("Symbol")
        )
        symbol = _str(
            record.get("Symbol")
            or record.get("Name")
            or record.get("SyscallName")
            or record.get("Type")
        )

        # Heuristic: if the owning module is identified and is NOT a known
        # kernel module, it has been hooked by a loadable module / kext.
        is_hooked = False
        if module:
            mod_lower = module.lower().strip("\\")
            is_hooked = mod_lower not in self._KERNEL_MODULES and not mod_lower.startswith("nt")

        return {
            "index": _str(record.get("Index") or record.get("Number") or record.get("Syscall")),
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
        key   = _str(record.get("Variable") or record.get("Key") or record.get("Name"))
        value = _str(record.get("Value") or record.get("Data"))
        if not key:
            return None

        key_upper = key.upper()
        is_preload_key = key_upper in self._SUSPICIOUS_KEYS
        value_lower = (value or "").lower()
        is_suspicious = is_preload_key or any(f in value_lower for f in self._SUSPICIOUS_VALUE_FRAGMENTS)

        return {
            "pid": _int(record.get("PID") or record.get("Pid")),
            "process": _str(record.get("Process") or record.get("Comm")),
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
            record.get("Permissions") or record.get("Protection")
            or record.get("Prot") or record.get("VmFlags")
        )
        path = _str(record.get("File") or record.get("Path") or record.get("MappedFile"))

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
        pid = record.get("PID") or record.get("Pid")
        process = _str(record.get("Process") or record.get("ImageFileName"))
        return {
            "pid": _int(pid),
            "process": process,
            "syscall": _str(record.get("Syscall") or record.get("SyscallName") or record.get("Name")),
            "address": _hex(record.get("Address") or record.get("Handler")),
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
