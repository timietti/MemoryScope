# backend/core/plugins/registry.py
"""
Central registry mapping OS → plugins to run, grouped by forensic domain.
Each entry defines the plugin name, domain, priority, and parser class.

Priority values map to the document's tiers:
  10 = Priority 1 (triage — run first)
  20 = Priority 2 (deeper investigation)
  30 = Priority 3 (situational / supporting evidence)
  40 = Priority 4 (informational / utility — not directly malware-focused)
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
from .parsers.syscall_direct import SyscallDirectParser


PLUGIN_REGISTRY: list[PluginSpec] = [

    # ══════════════════════════════════════════════════════════════════════════
    # WINDOWS  (77 plugins)
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
    PluginSpec("windows.malware.direct_system_calls",   "code_injection", 20, SyscallDirectParser, ["windows"],
               "Detects syscall instructions executed from outside ntdll.dll"),
    PluginSpec("windows.malware.indirect_system_calls", "code_injection", 20, SyscallDirectParser, ["windows"],
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

    # ── Priority 4 — Informational / Utility ─────────────────────────────────

    # Process Analysis (P4)
    PluginSpec("windows.cmdscan",   "process_analysis", 40, GenericParser, ["windows"],
               "Command history from cmd.exe console host buffers — historical attacker commands"),
    PluginSpec("windows.consoles",  "process_analysis", 40, GenericParser, ["windows"],
               "Full console I/O (input + output) from conhost structures — see what attacker saw"),
    PluginSpec("windows.sessions",  "process_analysis", 40, GenericParser, ["windows"],
               "Session assignment per process — distinguish RDP sessions from local console"),
    PluginSpec("windows.threads",   "memory_artifacts", 40, GenericParser, ["windows"],
               "All process threads with start addresses — find threads starting in injected memory"),
    PluginSpec("windows.suspended_threads", "code_injection", 40, GenericParser, ["windows"],
               "Threads in suspended state — hallmark of CREATE_SUSPENDED used in hollowing/injection"),
    PluginSpec("windows.joblinks",  "memory_artifacts", 40, GenericParser, ["windows"],
               "Job object groupings — unusual job objects may indicate sandbox manipulation"),

    # Credentials (P4)
    PluginSpec("windows.getsids",           "credentials", 40, GenericParser, ["windows"],
               "SIDs for each process — identifies privilege escalation and unexpected security contexts"),
    PluginSpec("windows.getservicesids",    "credentials", 40, GenericParser, ["windows"],
               "Service SID tokens — verify expected service SIDs per hosting process"),
    PluginSpec("windows.privileges",        "credentials", 40, GenericParser, ["windows"],
               "Process token privileges — flag SeDebugPrivilege, SeLoadDriverPrivilege, SeImpersonatePrivilege"),
    PluginSpec("windows.malware.skeleton_key_check", "credentials", 40, GenericParser, ["windows"],
               "Detects Skeleton Key domain controller malware — LSASS patches for any-password auth"),
    PluginSpec("windows.registry.certificates", "credentials", 40, GenericParser, ["windows"],
               "Certificates in the registry Certificate Store — rogue root CAs for MITM attacks"),

    # Network (P4)
    PluginSpec("windows.netstat",   "network", 40, NetstatParser, ["windows"],
               "Kernel-structure network traversal — second enumeration path complementing netscan"),

    # Persistence (P4)
    PluginSpec("windows.svclist",               "persistence", 40, GenericParser, ["windows"],
               "Services linked to running processes — maps each service to its hosting svchost"),
    PluginSpec("windows.registry.hivelist",     "persistence", 40, RegistryParser, ["windows"],
               "Registry hives loaded in memory — detect hives from non-standard paths"),
    PluginSpec("windows.registry.hivescan",     "persistence", 40, RegistryParser, ["windows"],
               "Pool scan for registry hive structures — finds hives absent from the active list"),
    PluginSpec("windows.registry.amcache",      "persistence", 40, RegistryParser, ["windows"],
               "AmCache application execution records — timestamps, file paths, and SHA1 hashes"),
    PluginSpec("windows.registry.userassist",   "persistence", 40, RegistryParser, ["windows"],
               "UserAssist GUI execution history — programs launched via Explorer with timestamps"),
    PluginSpec("windows.registry.scheduled_tasks", "persistence", 40, RegistryParser, ["windows"],
               "Scheduled tasks decoded from registry — memory-resident tasks survive disk cleanup"),
    PluginSpec("windows.shimcachemem",          "persistence", 40, GenericParser, ["windows"],
               "Shimcache (AppCompatCache) execution records from memory — historical file execution"),

    # Code Injection (P4)
    PluginSpec("windows.malware.unhooked_system_calls", "code_injection", 40, GenericParser, ["windows"],
               "Detects inline hooks on ntdll.dll syscall stubs — by EDR or malware"),
    PluginSpec("windows.etwpatch",  "code_injection", 40, GenericParser, ["windows"],
               "Detects ETW patching — malware blinds security monitoring by patching event tracing"),
    PluginSpec("windows.iat",       "code_injection", 40, GenericParser, ["windows"],
               "Import Address Table analysis — IAT hooks redirect API calls to attacker code"),
    PluginSpec("windows.debugregisters", "memory_artifacts", 40, GenericParser, ["windows"],
               "Hardware debug register values per thread — hardware breakpoints on API addresses"),

    # Rootkits (P4)
    PluginSpec("windows.malware.drivermodule",  "rootkits", 40, GenericParser, ["windows"],
               "Cross-references driver objects vs. module list — finds DKOM-hidden drivers"),
    PluginSpec("windows.modscan",               "rootkits", 40, ModulesParser, ["windows"],
               "Pool scan for kernel module structures — finds modules absent from PsLoadedModuleList"),
    PluginSpec("windows.unloadedmodules",        "rootkits", 40, ModulesParser, ["windows"],
               "Recently unloaded kernel modules — attacker may load then unload a privilege-esc driver"),
    PluginSpec("windows.devicetree",            "rootkits", 40, GenericParser, ["windows"],
               "Driver/device object tree — unknown filter drivers attached to filesystem/network stacks"),
    PluginSpec("windows.timers",                "rootkits", 40, GenericParser, ["windows"],
               "Kernel timer objects — rootkit beaconing and re-hooking callbacks"),
    PluginSpec("windows.registry.getcellroutine", "rootkits", 40, GenericParser, ["windows"],
               "Registry hives with hooked GetCellRoutine — deepest registry-level rootkit hiding"),
    PluginSpec("windows.orphan_kernel_threads", "rootkits", 40, GenericParser, ["windows"],
               "Kernel threads not backed by any loaded module — injected kernel-mode code indicator"),
    PluginSpec("windows.mbrscan",               "rootkits", 40, GenericParser, ["windows"],
               "Scans for MBR structures in memory — detects MBR bootkits"),

    # Memory Artifacts (P4)
    PluginSpec("windows.vadinfo",   "memory_artifacts", 40, GenericParser, ["windows"],
               "Detailed VAD region metadata — granular RWX / committed / file-backing information"),
    PluginSpec("windows.vadwalk",   "memory_artifacts", 40, GenericParser, ["windows"],
               "Walks the VAD tree hierarchy — supports vadinfo deep-dives and VAD integrity checks"),
    PluginSpec("windows.pe_symbols","memory_artifacts", 40, GenericParser, ["windows"],
               "PE export symbols and PDB paths — PDB paths may leak attacker build environment"),
    PluginSpec("windows.verinfo",   "memory_artifacts", 40, GenericParser, ["windows"],
               "PE version info from memory — detects masquerading (non-Microsoft svchost.exe etc.)"),
    PluginSpec("windows.bigpools",  "memory_artifacts", 40, GenericParser, ["windows"],
               "Large kernel pool allocations — large unknown-tagged allocations from suspicious drivers"),
    PluginSpec("windows.poolscanner","memory_artifacts",40, GenericParser, ["windows"],
               "Generic pool tag scanner — building block for custom object-type forensic searches"),
    PluginSpec("windows.virtmap",   "memory_artifacts", 40, GenericParser, ["windows"],
               "Virtual mapped sections in kernel memory — files mapped from unusual paths"),
    PluginSpec("windows.strings",   "memory_artifacts", 40, GenericParser, ["windows"],
               "Maps strings utility output to owning processes — IOC-string attribution"),
    PluginSpec("windows.suspicious_threads", "code_injection", 40, GenericParser, ["windows"],
               "Threads with start addresses outside known modules — active injected code execution"),

    # File System (P4)
    PluginSpec("windows.mftscan",   "filesystem", 40, GenericParser, ["windows"],
               "NTFS MFT FILE records from memory — deleted files and alternate data streams (ADS)"),
    PluginSpec("windows.symlinkscan","filesystem", 40, GenericParser, ["windows"],
               "Symbolic link objects — object manager path redirection by attackers"),

    # GUI Artifacts (P4) — Windows only
    PluginSpec("windows.deskscan",      "gui_artifacts", 40, GenericParser, ["windows"],
               "Desktop objects scan — hidden desktops used by malware for invisible GUI automation"),
    PluginSpec("windows.desktops",      "gui_artifacts", 40, GenericParser, ["windows"],
               "Desktop objects via list walking — complements deskscan; extra desktops are suspicious"),
    PluginSpec("windows.windows",       "gui_artifacts", 40, GenericParser, ["windows"],
               "All GUI window handles — hidden windows used as C2 message-passing channels"),
    PluginSpec("windows.windowstations","gui_artifacts", 40, GenericParser, ["windows"],
               "Window station objects — non-standard stations beyond WinSta0 are unusual"),

    # System Info (P4)
    PluginSpec("windows.kpcrs",     "system_info", 40, GenericParser, ["windows"],
               "KPCR structures per processor — modified IDT/GDT pointers indicate deep hooking"),
    PluginSpec("windows.crashinfo", "system_info", 40, GenericParser, ["windows"],
               "Crash dump header — bug check code may indicate rootkit-caused BSOD"),
    PluginSpec("windows.statistics","system_info", 40, GenericParser, ["windows"],
               "Memory image statistics — high invalid-page ratio may indicate anti-forensics"),


    # ══════════════════════════════════════════════════════════════════════════
    # LINUX  (41 plugins)
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

    # ── Priority 4 — Informational / Utility ─────────────────────────────────

    # Process Analysis (P4)
    PluginSpec("linux.pidhashtable",  "process_analysis", 40, PslistParser, ["linux"],
               "Third process enumeration path via PID hash table — catches rootkits incomplete in hiding"),
    PluginSpec("linux.pscallstack",   "process_analysis", 40, GenericParser, ["linux"],
               "Kernel call stacks at dump time — processes blocked in rootkit module functions"),
    PluginSpec("linux.capabilities",  "process_analysis", 40, GenericParser, ["linux"],
               "Process Linux capabilities — flag CAP_SYS_MODULE, CAP_SYS_PTRACE, CAP_NET_RAW"),
    PluginSpec("linux.ptrace",        "process_analysis", 40, GenericParser, ["linux"],
               "ptrace tracer-tracee relationships — unexpected ptracing of sshd or web servers"),

    # Network (P4)
    PluginSpec("linux.sockscan",  "network", 40, NetstatParser, ["linux"],
               "Socket scan — finds sockets hidden from sockstat by comparing scan vs list walk"),
    PluginSpec("linux.ip.Addr",   "network", 40, GenericParser, ["linux"],
               "Network interface IP addresses — unexpected IPs may indicate attacker VPN tunnels"),
    PluginSpec("linux.ip.Link",   "network", 40, GenericParser, ["linux"],
               "Interface link-layer flags — PROMISC flag indicates active network sniffing"),

    # Rootkits (P4)
    PluginSpec("linux.kthreads",              "rootkits", 40, GenericParser, ["linux"],
               "Kernel thread functions — kthreads in loadable module space suggest rootkit callbacks"),
    PluginSpec("linux.ebpf",                  "rootkits", 40, GenericParser, ["linux"],
               "Loaded eBPF programs — weaponized eBPF rootkits (ebpfkit, pamspy, TripleCross)"),
    PluginSpec("linux.tracing.perf_events",   "rootkits", 40, GenericParser, ["linux"],
               "Perf events — attacker-registered perf events monitoring sensitive kernel functions"),
    PluginSpec("linux.tracing.tracepoints",   "rootkits", 40, KernelHookParser, ["linux"],
               "Tracepoint callbacks in loadable module addresses — rootkit syscall interception"),

    # File System (P4)
    PluginSpec("linux.mountinfo",  "filesystem", 40, GenericParser, ["linux"],
               "Mount points across namespaces — overlay mounts hiding modifications, unexpected NFS"),

    # System Info (P4)
    PluginSpec("linux.kallsyms",   "system_info", 40, GenericParser, ["linux"],
               "Kernel symbol table — resolves mystery addresses from check_syscall / check_idt"),
    PluginSpec("linux.kmsg",       "system_info", 40, GenericParser, ["linux"],
               "Kernel log buffer (dmesg) — module load events, OOM (cryptominer), security denials"),
    PluginSpec("linux.boottime",   "system_info", 40, GenericParser, ["linux"],
               "System boot timestamp — recent reboot may indicate bootkit or evidence clearing"),
    PluginSpec("linux.iomem",      "system_info", 40, GenericParser, ["linux"],
               "Physical memory region map — validates acquisition completeness"),
    PluginSpec("linux.vmcoreinfo", "system_info", 40, GenericParser, ["linux"],
               "VMCoreInfo table — validates image metadata and kernel version identification"),


    # ══════════════════════════════════════════════════════════════════════════
    # macOS  (24 plugins)
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

    # ── Priority 4 — Informational / Utility ─────────────────────────────────

    # Network (P4)
    PluginSpec("mac.ifconfig",   "network",    40, GenericParser, ["macos"],
               "Interface flags and IPs — PROMISC flag indicates sniffing; unexpected utun/ipsec tunnels"),

    # File System (P4)
    PluginSpec("mac.list_files", "filesystem", 40, GenericParser, ["macos"],
               "Files in kernel vnode cache — reveals recently-deleted attacker tools"),
    PluginSpec("mac.vfsevents",  "filesystem", 40, GenericParser, ["macos"],
               "Processes monitoring VFS events — unknown watchers may detect investigation tools"),

    # Memory Artifacts (P4)
    PluginSpec("mac.kevents",    "memory_artifacts", 40, GenericParser, ["macos"],
               "Kernel event filters per process — surveillance of filesystem or process events"),


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
