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

    def parse(self, data: dict) -> list[dict]:
        """Convert raw Volatility3 JSON output to list of typed records."""
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
    def normalise(self, record: dict) -> dict | None:
        return {
            "pid": _int(record.get("PID") or record.get("Pid")),
            "ppid": _int(record.get("PPID") or record.get("PPid")),
            "name": _str(record.get("ImageFileName") or record.get("Name") or record.get("COMM")),
            "offset": _hex(record.get("Offset(V)") or record.get("Offset")),
            "threads": _int(record.get("Threads")),
            "handles": _int(record.get("Handles")),
            "wow64": _bool(record.get("Wow64")),
            "create_time": _str(record.get("CreateTime")),
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


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/plugins/parsers/handles.py

class HandlesParser(BaseParser):
    # Mutex names known to be used by malware families
    KNOWN_BAD_MUTEXES = {
        "Global\\MsWinZonesCacheCounterMutexA",  # KINS/ZeuS
        "ZupdService", "_AVIRA_", "IESQMMUTEX",
    }

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
