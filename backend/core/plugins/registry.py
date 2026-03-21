# backend/core/plugins/registry.py
"""
Central registry mapping OS → plugins to run, grouped by forensic domain.
Each entry defines the plugin name, domain, priority, and parser class.
"""
from dataclasses import dataclass, field
from typing import Type
from .parsers.base import BaseParser


@dataclass
class PluginSpec:
    name: str                      # Volatility3 plugin name, e.g. "windows.malfind"
    domain: str                    # Forensic domain for grouping
    priority: int                  # Lower = run first; high-value plugins run early
    parser: Type[BaseParser]       # Parser class for structured output
    os: list[str]                  # Compatible OS types
    description: str = ""
    extra_args: list[str] = field(default_factory=list)  # Additional CLI flags
    can_dump_files: bool = False   # Whether this plugin extracts files (needs extra isolation)


# Import parsers (defined in parsers/)
from .parsers.generic import GenericParser
from .parsers.pslist import PslistParser
from .parsers.pstree import PstreeParser
from .parsers.cmdline import CmdlineParser
from .parsers.dlllist import DlllistParser
from .parsers.malfind import MalfindParser
from .parsers.netstat import NetstatParser
from .parsers.modules import ModulesParser
from .parsers.registry import RegistryParser
from .parsers.handles import HandlesParser
from .parsers.filescan import FilescanParser
from .parsers.hashdump import HashdumpParser
from .parsers.linux_bash import LinuxBashParser
from .parsers.linux_lsmod import LinuxLsmodParser


PLUGIN_REGISTRY: list[PluginSpec] = [

    # ── PROCESS ANALYSIS ──────────────────────────────────────────────────────
    PluginSpec("windows.pslist",       "process_analysis", 10, PslistParser,  ["windows"],
               "Enumerate processes from EPROCESS linked list"),
    PluginSpec("windows.pstree",       "process_analysis", 11, PstreeParser,  ["windows"],
               "Process tree showing parent-child relationships"),
    PluginSpec("windows.cmdline",      "process_analysis", 12, CmdlineParser, ["windows"],
               "Command-line arguments for each process"),
    PluginSpec("windows.dlllist",      "process_analysis", 13, DlllistParser, ["windows"],
               "DLLs loaded in each process; detects injection"),
    PluginSpec("windows.envars",       "process_analysis", 14, GenericParser, ["windows"],
               "Environment variables per process"),
    PluginSpec("linux.pslist",         "process_analysis", 10, PslistParser,  ["linux"],
               "Linux process list from task_struct"),
    PluginSpec("linux.pstree",         "process_analysis", 11, PstreeParser,  ["linux"],
               "Linux process tree"),
    PluginSpec("linux.psaux",          "process_analysis", 12, GenericParser, ["linux"],
               "Linux process auxiliary info (cmdline, env)"),
    PluginSpec("mac.pslist",           "process_analysis", 10, PslistParser,  ["macos"],
               "macOS process list"),
    PluginSpec("mac.pstree",           "process_analysis", 11, PstreeParser,  ["macos"],
               "macOS process tree"),

    # ── CODE INJECTION ────────────────────────────────────────────────────────
    PluginSpec("windows.malfind",      "code_injection",   5,  MalfindParser, ["windows"],
               "Find injected code via RWX memory + PE header detection"),
    PluginSpec("windows.vadinfo",      "code_injection",   6,  GenericParser, ["windows"],
               "VAD node protection flags — detect unusual memory permissions"),
    PluginSpec("windows.vadyarascan",  "code_injection",   7,  GenericParser, ["windows"],
               "YARA scan over VAD regions", extra_args=["--yara-rules", "/opt/yara/injection.yar"]),

    # ── NETWORK ───────────────────────────────────────────────────────────────
    PluginSpec("windows.netstat",      "network",          5,  NetstatParser, ["windows"],
               "Active and recently closed network connections"),
    PluginSpec("windows.netscan",      "network",          6,  NetstatParser, ["windows"],
               "Pool-scan for connection objects (finds closed sessions)"),
    PluginSpec("linux.netstat",        "network",          5,  NetstatParser, ["linux"],
               "Linux active network connections"),
    PluginSpec("mac.netstat",          "network",          5,  NetstatParser, ["macos"],
               "macOS network connections"),

    # ── PERSISTENCE ───────────────────────────────────────────────────────────
    PluginSpec("windows.registry.hivelist",  "persistence", 10, RegistryParser, ["windows"],
               "Enumerate loaded registry hives"),
    PluginSpec("windows.registry.printkey", "persistence",  11, RegistryParser, ["windows"],
               "Read registry keys: Run, RunOnce, Services, AppInit_DLLs",
               extra_args=["--key", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"]),
    PluginSpec("windows.scheduled_tasks",   "persistence",  12, GenericParser, ["windows"],
               "Scheduled tasks extracted from registry/memory"),
    PluginSpec("windows.services",          "persistence",  13, GenericParser, ["windows"],
               "Windows services — detect malicious service installations"),
    PluginSpec("linux.bash",           "persistence",   10, LinuxBashParser, ["linux"],
               "Recover bash command history from memory"),
    PluginSpec("linux.crontab",        "persistence",   11, GenericParser,   ["linux"],
               "Crontab entries from memory"),
    PluginSpec("mac.bash",             "persistence",   10, LinuxBashParser, ["macos"],
               "macOS bash history"),

    # ── DRIVERS & ROOTKITS ────────────────────────────────────────────────────
    PluginSpec("windows.modules",      "rootkits",      5,  ModulesParser, ["windows"],
               "List kernel modules from PsLoadedModuleList"),
    PluginSpec("windows.driverscan",   "rootkits",      6,  ModulesParser, ["windows"],
               "Pool-scan for DRIVER_OBJECT — finds DKOM-hidden drivers"),
    PluginSpec("windows.ssdt",         "rootkits",      7,  GenericParser, ["windows"],
               "System Service Descriptor Table hooks — kernel rootkit indicator"),
    PluginSpec("windows.callbacks",    "rootkits",      8,  GenericParser, ["windows"],
               "Kernel notification callbacks (PsSetCreateProcessNotify etc.)"),
    PluginSpec("linux.lsmod",          "rootkits",      5,  LinuxLsmodParser, ["linux"],
               "Loaded kernel modules"),
    PluginSpec("linux.check_modules",  "rootkits",      6,  LinuxLsmodParser, ["linux"],
               "Compare module lists to detect hidden LKMs"),
    PluginSpec("linux.check_syscall",  "rootkits",      7,  GenericParser,    ["linux"],
               "Syscall table hooks"),

    # ── HANDLES & OBJECTS ─────────────────────────────────────────────────────
    PluginSpec("windows.handles",      "memory_artifacts", 15, HandlesParser, ["windows"],
               "Open handles: mutexes, files, registry keys — malware IOC fingerprints"),

    # ── FILE SYSTEM ───────────────────────────────────────────────────────────
    PluginSpec("windows.filescan",     "filesystem",    15, FilescanParser, ["windows"],
               "Pool-scan for FILE_OBJECT structures"),
    PluginSpec("windows.dumpfiles",    "filesystem",    20, FilescanParser, ["windows"],
               "Extract file contents from memory cache", can_dump_files=True),

    # ── CREDENTIALS ───────────────────────────────────────────────────────────
    PluginSpec("windows.hashdump",     "credentials",   10, HashdumpParser, ["windows"],
               "Extract NTLM password hashes from SAM/SYSTEM hives"),
    PluginSpec("windows.lsadump",      "credentials",   11, HashdumpParser, ["windows"],
               "LSA secrets — service account credentials"),

    # ── MEMORY STRINGS ────────────────────────────────────────────────────────
    PluginSpec("windows.strings",      "memory_strings", 30, GenericParser, ["windows"],
               "Extract printable strings mapped to owning processes"),
    PluginSpec("linux.strings",        "memory_strings", 30, GenericParser, ["linux"],
               "Linux memory strings"),

    # ── SYSTEM INFO ───────────────────────────────────────────────────────────
    PluginSpec("windows.info",         "system_info",   1, GenericParser, ["windows"],
               "System information and Volatility version"),
    PluginSpec("linux.banners",        "system_info",   1, GenericParser, ["linux"],
               "Linux kernel banner / version string"),
    PluginSpec("mac.banners",          "system_info",   1, GenericParser, ["macos"],
               "macOS kernel version banner"),
]


def get_plugins_for_os(os_type: str) -> list[PluginSpec]:
    """Return plugins applicable to the detected OS, sorted by priority."""
    return sorted(
        [p for p in PLUGIN_REGISTRY if os_type in p.os],
        key=lambda p: p.priority
    )


def get_plugin(name: str) -> PluginSpec | None:
    return next((p for p in PLUGIN_REGISTRY if p.name == name), None)
