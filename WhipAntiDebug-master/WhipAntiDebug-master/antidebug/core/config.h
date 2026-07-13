// ===== file: antidebug/core/config.h =====
#ifndef ANTIDEBUG_CONFIG_H
#define ANTIDEBUG_CONFIG_H

// ---------------------------------------------------------------------------
// Feature toggles — set to 0 to compile out a check entirely
// ---------------------------------------------------------------------------
// All AD_ENABLE_* are wrapped in #ifndef so a consumer can predefine 0 BEFORE
// including any framework header. Used by Sentinel_bridge.c to suppress
// AV/EDR false positives (ntdll hooks, process scans, handle scans, etc.).
//
// PRODUCTION MODE — all checks enabled by default
#ifndef AD_ENABLE_PEB_BEING_DEBUGGED
#define AD_ENABLE_PEB_BEING_DEBUGGED    1
#endif
#ifndef AD_ENABLE_PEB_NT_GLOBAL_FLAG
#define AD_ENABLE_PEB_NT_GLOBAL_FLAG    1
#endif
#ifndef AD_ENABLE_HEAP_FLAGS
#define AD_ENABLE_HEAP_FLAGS            1
#endif
#ifndef AD_ENABLE_DEBUG_PORT
#define AD_ENABLE_DEBUG_PORT            1
#endif
#ifndef AD_ENABLE_DEBUG_FLAGS
#define AD_ENABLE_DEBUG_FLAGS           1
#endif
#ifndef AD_ENABLE_HARDWARE_BP
#define AD_ENABLE_HARDWARE_BP           1
#endif
#ifndef AD_ENABLE_RDTSC_TIMING
#define AD_ENABLE_RDTSC_TIMING          1
#endif
#ifndef AD_ENABLE_RDTSC_DOUBLE
#define AD_ENABLE_RDTSC_DOUBLE          1
#endif
#ifndef AD_ENABLE_LOOP_TIMING
#define AD_ENABLE_LOOP_TIMING           1
#endif
#ifndef AD_ENABLE_INT3_SCAN
#define AD_ENABLE_INT3_SCAN             1
#endif
#ifndef AD_ENABLE_SEH_CHECK
#define AD_ENABLE_SEH_CHECK             1
#endif
#ifndef AD_ENABLE_HIDE_THREAD
#define AD_ENABLE_HIDE_THREAD           1
#endif
#ifndef AD_ENABLE_VM_HYPERVISOR
#define AD_ENABLE_VM_HYPERVISOR         1
#endif
#ifndef AD_ENABLE_VM_RDTSC
#define AD_ENABLE_VM_RDTSC              1
#endif
#ifndef AD_ENABLE_CODE_INTEGRITY
#define AD_ENABLE_CODE_INTEGRITY        1
#endif
#ifndef AD_ENABLE_KERNEL_DEBUGGER
#define AD_ENABLE_KERNEL_DEBUGGER       1
#endif
#ifndef AD_ENABLE_CLOSE_HANDLE_TRAP
#define AD_ENABLE_CLOSE_HANDLE_TRAP     1
#endif
#ifndef AD_ENABLE_QPC_TIMING
#define AD_ENABLE_QPC_TIMING            1
#endif
#ifndef AD_ENABLE_DEBUG_OBJECT_REMOVE
#define AD_ENABLE_DEBUG_OBJECT_REMOVE   1
#endif
#ifndef AD_ENABLE_HOOK_DETECT
#define AD_ENABLE_HOOK_DETECT           0   // FP: AV/EDR hookent ntdll stubs
#endif
#ifndef AD_ENABLE_GUARD_PAGE_TRAP
#define AD_ENABLE_GUARD_PAGE_TRAP       1
#endif
#ifndef AD_ENABLE_DR_CANARY
#define AD_ENABLE_DR_CANARY             1
#endif
#ifndef AD_ENABLE_SUSPICIOUS_MODULES
#define AD_ENABLE_SUSPICIOUS_MODULES    0   // FP: DLL injectées par AV/overlay
#endif
#ifndef AD_ENABLE_INSTRUMENTATION_CB
#define AD_ENABLE_INSTRUMENTATION_CB    0   // FP: EDR set PROCESS_INSTRUMENTATION_CALLBACK
#endif

// ---------------------------------------------------------------------------
// Correlation-engine extension facts (added 2026-04-27)
// ---------------------------------------------------------------------------
// KdDebuggerEnabled / KdDebuggerNotPresent read from KUSER_SHARED_DATA fed
// into the correlation truth table. Catches kernel-debugger stealth where
// PEB hooks hide BeingDebugged but KUSD (read-only kernel page at fixed
// 0x7FFE0000) still reflects the real state.
#ifndef AD_ENABLE_KD_PRESENT
#define AD_ENABLE_KD_PRESENT            1
#endif
// First-byte audit of ntdll!DbgBreakPoint fed into correlation. We never
// patch DbgBreakPoint ourselves, so any value other than 0xCC is a hook
// from outside — combined with PEB-clean it raises a contradiction.
#ifndef AD_ENABLE_DBGBREAK_AUDIT
#define AD_ENABLE_DBGBREAK_AUDIT        1
#endif

// ---------------------------------------------------------------------------
// al-khaser-inspired checks (new)
// ---------------------------------------------------------------------------
// Parent process: check if parent exe is a known debugger (x64dbg, WinDbg…)
#ifndef AD_ENABLE_PARENT_PROCESS
#define AD_ENABLE_PARENT_PROCESS        1
#endif
// SeDebugPrivilege: flag if our token has SeDebug enabled (should never happen)
#ifndef AD_ENABLE_SE_DEBUG
#define AD_ENABLE_SE_DEBUG              1
#endif
// WriteWatch: detect sandbox/DBI instrumentation via MEM_WRITE_WATCH pages
#ifndef AD_ENABLE_WRITE_WATCH
#define AD_ENABLE_WRITE_WATCH           1
#endif
// VM vendor: exact CPUID vendor string match (VMware, VBox, KVM, Hyper-V…)
#ifndef AD_ENABLE_VM_VENDOR
#define AD_ENABLE_VM_VENDOR             1
#endif

// ---------------------------------------------------------------------------
// Extra anti-debug checks (new)
// ---------------------------------------------------------------------------
// Hook detection on DbgUiRemoteBreakin / DbgBreakPoint / NtCreateDebugObject
#ifndef AD_ENABLE_DBGUI_PATCH
#define AD_ENABLE_DBGUI_PATCH           0   // FP: DbgUiRemoteBreakin hooké par AV
#endif
// System handle scan: find foreign processes holding debug handles to our PID
#ifndef AD_ENABLE_HANDLE_SCAN
#define AD_ENABLE_HANDLE_SCAN           1
#endif
// PEB LDR scan: detect injected debugger/instrumentation DLLs
#ifndef AD_ENABLE_DEBUGGER_DLLS
#define AD_ENABLE_DEBUGGER_DLLS         1
#endif
// Process list scan: find known debugger executables among all running processes
#ifndef AD_ENABLE_PROCESS_SCAN
#define AD_ENABLE_PROCESS_SCAN          0   // FP: noms debugger dans process AV
#endif
// Hash-based process scan: FNV-1a hashes of debugger names (no strings in binary)
#ifndef AD_ENABLE_PROCESS_SIG_SCAN
#define AD_ENABLE_PROCESS_SIG_SCAN      0   // FP: hash collision avec process AV
#endif
// ETW hook: detect hooks on EtwEventWrite / EtwEventWriteFull
#ifndef AD_ENABLE_ETW_HOOK
#define AD_ENABLE_ETW_HOOK              0   // FP: EDR hookent EtwEventWrite
#endif
// Trap flag: EFLAGS.TF single-step interception + context leak detection
#ifndef AD_ENABLE_TRAP_FLAG
#define AD_ENABLE_TRAP_FLAG             1
#endif

// ---------------------------------------------------------------------------
// Advanced anti-debug checks (new)
// ---------------------------------------------------------------------------
#define AD_ENABLE_BTB_TRIANGULATE       0   // Reliability: variations énormes Intel/AMD/Zen gens
#define AD_ENABLE_TSC_QPC_DRIFT         0   // Reliability: instable laptops (P/E cores, C-states)
#define AD_ENABLE_WIRESHARK             1   // Wireshark/tshark detection (real-time hook + static)
#define AD_ENABLE_ANTI_SCYLLAHIDE       1
#define AD_ENABLE_ANTI_TITANHIDE        1

// Baseline for ad_private_exec_scan(). Modern Win10/11 has 30-70 legitimate
// PRIVATE+EXEC regions (Defender AmsiScanBuffer, AppContainer, ETW, ...).
// Only count regions above this threshold as foreign code.
#define AD_PRIV_EXEC_BASELINE           70u
#define AD_ENABLE_GHOST_BREAKPOINTS     1
#define AD_ENABLE_PIPELINE_DESYNC       0   // Reliability: pipeline depth diffère trop entre uarchs
#define AD_ENABLE_SCHEDULER_SYNC        1
#define AD_ENABLE_EXCEPTION_FINGERPRINT 1
#define AD_ENABLE_IMPOSSIBLE_STATES     1
#define AD_ENABLE_SELFMOD_RACE          0   // Reliability: i-cache invalidation flaky AMD
#define AD_ENABLE_PRESSURE_TEST         1
#define AD_ENABLE_TEMPORAL_TRAPS        1
#define AD_ENABLE_CROSS_PROCESS         1
#define AD_ENABLE_HEISENBERG            0   // Reliability: bruit énorme sur CPU peu chargés
#define AD_ENABLE_WORKING_SET_PROBE     1
#define AD_ENABLE_EXCEPTION_RIP_ANCHOR  1

// ---------------------------------------------------------------------------
// Timing thresholds
// ---------------------------------------------------------------------------
// RDTSC single-step threshold (cycles): anything above this = suspicious
// Baseline: 2 x CPUID (~300 cycles) + 8 volatile muls (~80 cycles) = ~600 cycles.
// Threshold of 5000 leaves plenty of margin above noise while catching debuggers.
#define AD_RDTSC_STEP_THRESHOLD     5000ULL

// RDTSC double-read threshold: lfence alone costs ~40 cycles on modern CPUs.
// The check now takes the minimum across 5 runs to eliminate interrupt spikes.
// 1000 catches hypervisor RDTSC emulation (typically 5000-50000 cycles) while
// tolerating ~20× lfence overhead for any microarchitectural variance.
#define AD_RDTSC_DOUBLE_THRESHOLD   1000ULL

// Loop iteration count for the timing check
#define AD_LOOP_ITER_COUNT          800U

// Loop cycle budget: all iterations should finish under this on bare metal
#define AD_LOOP_CYCLE_THRESHOLD     200000ULL

// CPUID+RDTSC overhead threshold for VM detection (cycles)
// 3000 was too tight on AMD Ryzen (CPUID + RDTSC pair cost ~3500 cycles natively).
// 8000 keeps detection of Hyper-V / KVM exits (5,000-50,000 cycles) without FP.
#define AD_VM_RDTSC_THRESHOLD       8000ULL

// ---------------------------------------------------------------------------
// INT3 scan range (bytes from function pointer to search for 0xCC)
// ---------------------------------------------------------------------------
#define AD_INT3_SCAN_RANGE          128U

// ---------------------------------------------------------------------------
// Code integrity scan size (bytes from image base)
// ---------------------------------------------------------------------------
#define AD_CODE_HASH_REGION_SIZE    0x2000U   // 8 KB of .text

// ---------------------------------------------------------------------------
// Dispatcher PRNG seed — change this per build for uniqueness
// ---------------------------------------------------------------------------
#define AD_PRNG_SEED    0xC0FFEE13DEADB33FULL

// ---------------------------------------------------------------------------
// Dispatcher: skip probability (0..15). Values out of [0,15] are clamped.
// 0  = never skip a check
// 4  = ~25% chance of skipping any given check
// 8  = ~50% chance
// ---------------------------------------------------------------------------
#define AD_SKIP_PROBABILITY     3U

// ---------------------------------------------------------------------------
// Suspicion threshold: number of checks that must fire to call it "detected"
// ---------------------------------------------------------------------------
#define AD_SUSPICION_THRESHOLD  2U

// ---------------------------------------------------------------------------
// Direct-syscall verification, critical function scan, total elapsed time
// ---------------------------------------------------------------------------
#define AD_ENABLE_SYSCALL_VERIFY     1
#define AD_ENABLE_CRITICAL_SCAN      1
#define AD_ENABLE_TOTAL_ELAPSED      1
// PAGE_GUARD sentinel: bait page that trips when a debugger memory window reads it
#define AD_ENABLE_PAGE_GUARD_SENTINEL 1
// HWID/SMBIOS fingerprint: CPUID topology, KUSD profile, TSC freq, SMBIOS vendor
#define AD_ENABLE_HWID_FINGERPRINT   1

// Score noise floor: timing checks, ghost thread, pool workers, and watchdog
// startup all produce non-deterministic points on clean systems (~25-40 pts).
// Subtract this constant from the raw score to get the real debug signal.
// Recalibrate if clean-run scores exceed this value on the target machine.
#define AD_SCORE_NOISE_FLOOR         44U

// Internal testing mode: disables latent sentinel arming and liveness guard
// so the binary survives under a debugger long enough to test the VM
// meta-protections (Meta-A through Meta-E in vm_programs.h).
// NEVER define this in production builds.
#ifndef AD_TESTING_MODE
#define AD_TESTING_MODE              0
#endif

// Total elapsed RDTSC threshold: clean run ~1-10M, debugger with erun >30M
#define AD_ELAPSED_RDTSC_THRESHOLD   30000000ULL

// Total elapsed TickCount threshold: clean <3 ticks, debugger >10 ticks
#define AD_ELAPSED_TICK_THRESHOLD    10U

// ---------------------------------------------------------------------------
// Advanced check thresholds
// ---------------------------------------------------------------------------
#define AD_GHOST_BP_SCAN_SIZE       256U
#define AD_PIPELINE_DESYNC_SAMPLES  8U
#define AD_SCHEDULER_THREAD_PAIRS   2U
#define AD_TEMPORAL_TRAP_DELAY_SEC  5U
#define AD_PRESSURE_EXCEPTION_COUNT 200U

// ---------------------------------------------------------------------------
// New stealth & hardening features
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// DLL unload mode — master toggle that selects between two coherent profiles.
//
//   AD_DLL_UNLOADABLE = 1  (default)  — UNLOADABLE
//     * PE headers preserved
//     * Module stays linked in PEB.Ldr
//     * ad_dll_request_self_free() exported (clean shutdown path)
//     * DllMain DETACH performs best-effort thread/VEH teardown
//     * External FreeLibrary works
//     * Stealth: weaker (DLL is visible to module enumerators / dumpers)
//
//   AD_DLL_UNLOADABLE = 0  — FORTRESS (cannot be unloaded)
//     * PE headers erased after init (anti-dump)
//     * Module unlinked from PEB.Ldr → LdrUnloadDll returns STATUS_DLL_NOT_FOUND
//     * No self-free export
//     * External FreeLibrary fails — DLL is committed for the process lifetime
//     * Stealth: strong
//
// Individual sub-flags below can still be overridden if a custom profile
// is needed.
// ---------------------------------------------------------------------------
#ifndef AD_DLL_UNLOADABLE
#define AD_DLL_UNLOADABLE               1
#endif

#ifndef AD_ENABLE_PE_HEADER_ERASE
#define AD_ENABLE_PE_HEADER_ERASE       (!AD_DLL_UNLOADABLE)
#endif
#ifndef AD_ENABLE_MODULE_UNLINK
#define AD_ENABLE_MODULE_UNLINK         (!AD_DLL_UNLOADABLE)
#endif
// Encrypt .text section when not running checks (independent of unload mode)
#define AD_ENABLE_TEXT_ARMOR            0   // other threads (watchdog/sentinel) run in .text — need suspension protocol
// Cross-thread heartbeat (detect thread suspension)
#define AD_ENABLE_HEARTBEAT             1
// Encrypted score accumulation (prevent score patching between checks)
#define AD_ENABLE_SCORE_VAULT           1
// Remote debugger detection (TCP ports + named pipes)
#ifndef AD_ENABLE_REMOTE_DEBUG
#define AD_ENABLE_REMOTE_DEBUG          1
#endif
// Anti-emulation checks (CPUID/FPU/RDTSC edge cases)
#define AD_ENABLE_ANTI_EMULATION        1
// EPT split page detection (hypervisor read/exec page divergence)
#define AD_ENABLE_EPT_SPLIT             0   // FP: VBS/HVCI activé par défaut Win11 22H2+
// FindWindow debugger class scan
#ifndef AD_ENABLE_WINDOW_SCAN
#define AD_ENABLE_WINDOW_SCAN           1
#endif
// OutputDebugString timing
#define AD_ENABLE_ODS_TIMING            1
// Image File Execution Options debugger key
#define AD_ENABLE_IFEO_CHECK            1
// Job object detection (sandbox)
#define AD_ENABLE_JOB_CHECK             1
// UnhandledExceptionFilter hook detection
#ifndef AD_ENABLE_UEF_CHECK
#define AD_ENABLE_UEF_CHECK             0   // FP: App Verifier / Defender exploit guard
#endif
// NtSetDebugFilterState kernel debug probe
#define AD_ENABLE_DEBUG_FILTER          1
// Memory breakpoint timing (PAGE_GUARD detection)
#define AD_ENABLE_MEMORY_BP_TIMING      1
// ntdll page protection check (writable = hooks)
#ifndef AD_ENABLE_NTDLL_PAGE_CHECK
#define AD_ENABLE_NTDLL_PAGE_CHECK      0   // FP: EDR rendent ntdll RWX
#endif
// Polymorphic syscall gadgets (defeat single-point SyscallStub hooking)
#define AD_ENABLE_POLY_SYSCALL          1

// ---------------------------------------------------------------------------
// Behavioral debugger detection (name-independent)
// ---------------------------------------------------------------------------
// Self debug state: DebugPort + DebugObject + DebugFlags + PEB race
#define AD_ENABLE_DEBUGGER_BEHAVIOR     1
// Return address integrity check in ad_run_hardened
#define AD_ENABLE_RETADDR_CHECK         1

// ---------------------------------------------------------------------------
// VM detection — deep analysis (new)
// ---------------------------------------------------------------------------
// Deep CPUID: nested HV, brand scan, feature cross, PMC, thermal, topology
#define AD_ENABLE_VM_CPUID_DEEP         0   // FP: Hyper-V leaf 0x40000000 présent sur Win11 VBS
// Firmware: ACPI OEM strings, SMBIOS baseboard/chassis, BIOS date
#define AD_ENABLE_VM_FIRMWARE           1
// Device artifacts: VM DLL modules, module count, path anomaly
#define AD_ENABLE_VM_DEVICE             1
// I/O backdoor: VMware/VBox port probes, VMCALL, port timing
#define AD_ENABLE_VM_IO_BACKDOOR        0   // Reliability: peut crash sans SEH solide
// Memory anomaly: physical mem, uptime, proc cross, time, perf info
#define AD_ENABLE_VM_MEMORY             1
// Timing VM exit: leaf timing, IN timing, granularity, serialization
#define AD_ENABLE_VM_TIMING             0   // FP: VMEXIT timing FP avec Hyper-V/VBS host

#endif // ANTIDEBUG_CONFIG_H
