# backend/core/plugins/registry.py
"""
Central registry mapping OS → plugins to run, grouped by forensic domain.
Each entry defines the plugin name, domain, priority, and parser class.

Priority values map to the document's tiers:
  10 = Priority 1 (triage — run first)
  20 = Priority 2 (deeper investigation)
  30 = Priority 3 (situational / supporting evidence)
   1 = OS detection only (not shown in plugin selector)
"""
from dataclasses import dataclass, field
from typing import Type
from .parsers.base import BaseParser


@dataclass
class PluginSpec:
    name: str                      # Volatility3 plugin name, e.g. "windows.malware.malfind"
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
from .parsers.psxview import PsxviewParser
from .parsers.svcscan import SvcscanParser
from .parsers.ldrmodules import LdrmodulesParser
from .parsers.kernel_hook import KernelHookParser
from .parsers.lsof import LsofParser
from .parsers.envars import EnvarsParser
from .parsers.mem_maps import MemMapsParser


PLUGIN_REGISTRY: list[PluginSpec] = [

    # ══════════════════════════════════════════════════════════════════════════
    # WINDOWS  (27 plugins)
    # ══════════════════════════════════════════════════════════════════════════

    # ── Process Analysis ──────────────────────────────────────────────────────
    PluginSpec("windows.pslist",    "process_analysis", 10, PslistParser,  ["windows"],
               "Lists running processes from the EPROCESS linked list"),
    PluginSpec("windows.psscan",    "process_analysis", 10, PslistParser,  ["windows"],
               "Pool-tag scan for EPROCESS structures — finds hidden/terminated processes"),
    PluginSpec("windows.pstree",    "process_analysis", 10, PstreeParser,  ["windows"],
               "Process tree showing parent-child relationships"),
    PluginSpec("windows.cmdline",   "process_analysis", 10, CmdlineParser, ["windows"],
               "Command-line arguments for each process"),
    PluginSpec("windows.psxview",   "process_analysis", 10, PsxviewParser, ["windows"],
               "Cross-references multiple enumeration methods to detect hidden processes"),
    PluginSpec("windows.malware.pebmasquerade", "process_analysis", 10, GenericParser, ["windows"],
               "Detects PEB masquerading — tampered ImagePathName / CommandLine fields"),
    PluginSpec("windows.dlllist",   "process_analysis", 20, DlllistParser, ["windows"],
               "DLLs loaded per process — spot DLL side-loading and phantom injection"),
    PluginSpec("windows.envars",    "process_analysis", 30, EnvarsParser,  ["windows"],
               "Environment variables per process"),

    # ── Code Injection ────────────────────────────────────────────────────────
    PluginSpec("windows.malware.malfind",          "code_injection", 10, MalfindParser, ["windows"],
               "RWX memory regions with injected code — PE headers, shellcode, beacons"),
    PluginSpec("windows.malware.hollowprocesses",  "code_injection", 10, GenericParser, ["windows"],
               "Detects process hollowing — in-memory PE header vs on-disk image mismatch"),
    PluginSpec("windows.malware.ldrmodules",       "code_injection", 10, LdrmodulesParser, ["windows"],
               "Cross-references PEB loader lists to find unlinked (hidden) DLLs"),
    PluginSpec("windows.malware.processghosting",  "code_injection", 10, GenericParser, ["windows"],
               "Detects process ghosting — process image backed by a DeletePending file"),
    PluginSpec("windows.malware.direct_system_calls",   "code_injection", 20, GenericParser, ["windows"],
               "Detects syscall instructions executed from outside ntdll.dll"),
    PluginSpec("windows.malware.indirect_system_calls", "code_injection", 20, GenericParser, ["windows"],
               "Detects indirect syscall trampolines jumping into ntdll syscall stubs"),

    # ── Network ───────────────────────────────────────────────────────────────
    PluginSpec("windows.netscan",   "network", 10, NetstatParser, ["windows"],
               "Scans for TCP/UDP connection objects — active and recently closed"),

    # ── Persistence ───────────────────────────────────────────────────────────
    PluginSpec("windows.svcscan",              "persistence", 10, SvcscanParser,  ["windows"],
               "Windows services from memory — survives registry cleanup"),
    PluginSpec("windows.registry.printkey",    "persistence", 20, RegistryParser,  ["windows"],
               "Registry Run/RunOnce/Services keys — persistence locations",
               extra_args=["--key", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"]),

    # ── Rootkits / Drivers ────────────────────────────────────────────────────
    PluginSpec("windows.ssdt",      "rootkits", 20, KernelHookParser, ["windows"],
               "SSDT entries — kernel-mode syscall hooks"),
    PluginSpec("windows.callbacks", "rootkits", 20, KernelHookParser, ["windows"],
               "Kernel notification callbacks (process, thread, image, registry)"),
    PluginSpec("windows.driverirp", "rootkits", 20, KernelHookParser, ["windows"],
               "IRP dispatch table entries — detect IRP hooking by rootkits"),
    PluginSpec("windows.driverscan","rootkits", 20, ModulesParser, ["windows"],
               "Pool-scan for DRIVER_OBJECT — finds DKOM-hidden drivers"),
    PluginSpec("windows.modules",   "rootkits", 20, ModulesParser, ["windows"],
               "Loaded kernel modules from PsLoadedModuleList"),
    PluginSpec("windows.malware.svcdiff", "rootkits", 20, SvcscanParser, ["windows"],
               "Differential analysis: list-walk vs pool-scan to expose hidden services"),

    # ── Credentials ───────────────────────────────────────────────────────────
    PluginSpec("windows.registry.hashdump", "credentials", 20, HashdumpParser, ["windows"],
               "NTLM password hashes from the SAM hive"),

    # ── Memory Artifacts ──────────────────────────────────────────────────────
    PluginSpec("windows.handles",   "memory_artifacts", 20, HandlesParser, ["windows"],
               "Open handles — mutexes, named pipes, files, registry keys"),
    PluginSpec("windows.mutantscan","memory_artifacts", 30, GenericParser, ["windows"],
               "Mutex objects — malware single-instance markers and family fingerprints"),

    # ── File System ───────────────────────────────────────────────────────────
    PluginSpec("windows.filescan",  "filesystem", 30, FilescanParser, ["windows"],
               "FILE_OBJECT pool scan — dropped malware, exfiltration staging files"),


    # ══════════════════════════════════════════════════════════════════════════
    # LINUX  (24 plugins)
    # ══════════════════════════════════════════════════════════════════════════

    # ── Process Analysis ──────────────────────────────────────────────────────
    PluginSpec("linux.pslist",  "process_analysis", 10, PslistParser,  ["linux"],
               "Process list from kernel task_struct linked list"),
    PluginSpec("linux.psscan",  "process_analysis", 10, PslistParser,  ["linux"],
               "Memory scan for task_struct — finds hidden / terminated processes"),
    PluginSpec("linux.pstree",  "process_analysis", 10, PstreeParser,  ["linux"],
               "Process tree — reveals web server shells, unusual cron children"),
    PluginSpec("linux.psaux",   "process_analysis", 10, GenericParser, ["linux"],
               "Processes with full command-line arguments"),
    PluginSpec("linux.envars",  "process_analysis", 20, EnvarsParser,  ["linux"],
               "Environment variables — LD_PRELOAD, PATH hijacking, HISTFILE=/dev/null"),
    PluginSpec("linux.malware.check_creds", "process_analysis", 20, GenericParser, ["linux"],
               "Processes with unexpected UID 0 or shared credential structures"),

    # ── Code Injection ────────────────────────────────────────────────────────
    PluginSpec("linux.malware.malfind", "code_injection", 10, MalfindParser, ["linux"],
               "Anonymous executable memory regions — injected ELFs, shellcode, fileless payloads"),
    PluginSpec("linux.library_list",    "code_injection", 20, GenericParser, ["linux"],
               "Loaded shared libraries — detects LD_PRELOAD hijacking and injected .so files"),
    PluginSpec("linux.elfs",            "code_injection", 20, GenericParser, ["linux"],
               "All memory-mapped ELF files — finds manually mapped / anonymously injected ELFs"),

    # ── Network ───────────────────────────────────────────────────────────────
    PluginSpec("linux.sockstat",           "network", 10, NetstatParser, ["linux"],
               "Network connections with owning process — C2, reverse shells, miner pools"),
    PluginSpec("linux.malware.check_afinfo","network", 20, KernelHookParser, ["linux"],
               "Network protocol handler function pointers — detects /proc/net hiding hooks"),
    PluginSpec("linux.malware.netfilter",   "network", 20, KernelHookParser, ["linux"],
               "Netfilter hooks — covert channels, ICMP backdoors, traffic manipulation"),

    # ── Persistence ───────────────────────────────────────────────────────────
    PluginSpec("linux.bash", "persistence", 10, LinuxBashParser, ["linux"],
               "Bash command history from memory — captures even after history clear"),

    # ── Rootkits / LKMs ───────────────────────────────────────────────────────
    PluginSpec("linux.lsmod",                   "rootkits", 10, LinuxLsmodParser, ["linux"],
               "Loaded kernel modules"),
    PluginSpec("linux.malware.hidden_modules",  "rootkits", 10, LinuxLsmodParser, ["linux"],
               "Memory carve for modules removed from the module list — LKM rootkits"),
    PluginSpec("linux.malware.check_syscall",   "rootkits", 10, KernelHookParser, ["linux"],
               "Syscall table hooks — primary LKM rootkit detection method"),
    PluginSpec("linux.malware.check_modules",   "rootkits", 10, LinuxLsmodParser, ["linux"],
               "Module list vs sysfs cross-view — discrepancies reveal hidden LKMs"),
    PluginSpec("linux.malware.modxview",        "rootkits", 10, LinuxLsmodParser, ["linux"],
               "Unified lsmod + check_modules + hidden_modules cross-view"),
    PluginSpec("linux.malware.check_idt",         "rootkits", 20, KernelHookParser, ["linux"],
               "IDT entries — interrupt descriptor table hooking by advanced rootkits"),
    PluginSpec("linux.malware.keyboard_notifiers","rootkits", 20, KernelHookParser, ["linux"],
               "Keyboard notifier chain — kernel-level keylogger detection"),
    PluginSpec("linux.tty_check",                 "rootkits", 20, KernelHookParser, ["linux"],
               "TTY device function pointer hooks — terminal I/O interception"),
    PluginSpec("linux.tracing.ftrace",            "rootkits", 20, KernelHookParser, ["linux"],
               "ftrace hooks — advanced rootkit technique bypassing syscall table checks"),

    # ── File System ───────────────────────────────────────────────────────────
    PluginSpec("linux.lsof",       "filesystem", 20, LsofParser,    ["linux"],
               "Open file descriptors — /etc/shadow access, raw device handles, sockets"),

    # ── Memory Artifacts ──────────────────────────────────────────────────────
    PluginSpec("linux.proc.Maps",  "memory_artifacts", 30, MemMapsParser, ["linux"],
               "Process memory map — full context for malfind hits, rwx anonymous regions"),


    # ══════════════════════════════════════════════════════════════════════════
    # macOS  (20 plugins)
    # ══════════════════════════════════════════════════════════════════════════

    # ── Process Analysis ──────────────────────────────────────────────────────
    PluginSpec("mac.pslist",  "process_analysis", 10, PslistParser,  ["macos"],
               "Process list — multi-method enumeration (allproc, tasks, PID hash table)"),
    PluginSpec("mac.pstree",  "process_analysis", 10, PstreeParser,  ["macos"],
               "Process tree — launchd spawning unexpected children"),
    PluginSpec("mac.psaux",   "process_analysis", 10, GenericParser, ["macos"],
               "Processes with full command-line arguments"),
    PluginSpec("mac.envars",  "process_analysis", 20, EnvarsParser,  ["macos"],
               "Environment variables — DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH hijacking"),

    # ── Code Injection ────────────────────────────────────────────────────────
    PluginSpec("mac.malfind", "code_injection", 10, MalfindParser, ["macos"],
               "Anonymous executable memory — injected Mach-O images and shellcode"),

    # ── Network ───────────────────────────────────────────────────────────────
    PluginSpec("mac.netstat",       "network", 10, NetstatParser, ["macos"],
               "Network connections per process — C2, reverse shells, data exfiltration"),
    PluginSpec("mac.socket_filters","network", 20, KernelHookParser, ["macos"],
               "Socket filter hooks — network traffic interception by kext rootkits"),

    # ── Persistence ───────────────────────────────────────────────────────────
    PluginSpec("mac.bash", "persistence", 10, LinuxBashParser, ["macos"],
               "Bash command history — captures even after history clear"),

    # ── Rootkits / Kexts ──────────────────────────────────────────────────────
    PluginSpec("mac.lsmod",            "rootkits", 10, LinuxLsmodParser, ["macos"],
               "Loaded kernel extensions (kexts)"),
    PluginSpec("mac.check_syscall",    "rootkits", 10, KernelHookParser, ["macos"],
               "BSD syscall table hooks — kernel-mode rootkit detection"),
    PluginSpec("mac.check_trap_table", "rootkits", 10, KernelHookParser, ["macos"],
               "Mach trap table hooks — intercepts Mach IPC below the BSD syscall layer"),
    PluginSpec("mac.check_sysctl",     "rootkits", 10, KernelHookParser, ["macos"],
               "Sysctl handler hooks — covert C2 interface registered by rootkits"),
    PluginSpec("mac.kauth_listeners",  "rootkits", 20, KernelHookParser, ["macos"],
               "kauth listeners — file/process authorization interception by rootkits"),
    PluginSpec("mac.kauth_scopes",     "rootkits", 30, GenericParser,    ["macos"],
               "kauth authorization scopes — cross-reference with kauth_listeners"),
    PluginSpec("mac.trustedbsd",       "rootkits", 30, GenericParser,    ["macos"],
               "TrustedBSD MAC policy modules — deepest kernel security interception layer"),
    PluginSpec("mac.timers",           "rootkits", 30, GenericParser,    ["macos"],
               "Kernel timers — rootkit beaconing, re-hiding, or C2 polling callbacks"),

    # ── File System ───────────────────────────────────────────────────────────
    PluginSpec("mac.lsof",  "filesystem", 20, LsofParser,    ["macos"],
               "Open file descriptors — Keychain access, SSH keys, sensitive DB files"),
    PluginSpec("mac.mount", "filesystem", 20, GenericParser, ["macos"],
               "Mounted filesystems — overlay mounts, unexpected NFS/SMB mounts"),

    # ── Memory Artifacts ──────────────────────────────────────────────────────
    PluginSpec("mac.proc_maps", "memory_artifacts", 20, MemMapsParser, ["macos"],
               "Process memory map — context for malfind hits, DYLD_INSERT_LIBRARIES regions"),

    # ── System Info ───────────────────────────────────────────────────────────
    PluginSpec("mac.dmesg", "system_info", 30, GenericParser, ["macos"],
               "Kernel log buffer — kext load messages, SIP violations, panic info"),


    # ══════════════════════════════════════════════════════════════════════════
    # OS DETECTION  (priority 1 — used by triage, not shown in plugin selector)
    # ══════════════════════════════════════════════════════════════════════════
    PluginSpec("windows.info", "system_info", 1, GenericParser, ["windows"],
               "System information and OS detection"),
    PluginSpec("banners",      "system_info", 1, GenericParser, ["linux", "macos"],
               "Kernel banner / version string — used for OS detection"),
]


def get_plugins_for_os(os_type: str) -> list[PluginSpec]:
    """Return plugins applicable to the detected OS, sorted by priority."""
    return sorted(
        [p for p in PLUGIN_REGISTRY if os_type in p.os],
        key=lambda p: p.priority
    )


def get_plugin(name: str) -> PluginSpec | None:
    return next((p for p in PLUGIN_REGISTRY if p.name == name), None)
