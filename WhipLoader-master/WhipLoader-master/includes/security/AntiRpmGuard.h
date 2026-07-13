#pragma once

// Anti-ReadProcessMemory guard for the WhipLoader process.
//
// Spawns a background thread that periodically enumerates every handle
// open in the system (NtQuerySystemInformation/SystemHandleInformation),
// filters those targeting OUR pid, and flags any external owner that
// has PROCESS_VM_READ or PROCESS_VM_OPERATION granted.
//
// Effect on detection: bumps Sentinel external-threat bits → all
// subsequent auth_tag computations are corrupted → server rejects the
// request → Phase 4 anomaly detection triggers an auto-ban via
// ViolationType.AUTH_TAG_MISMATCH.
//
// Limitations (see DUMP_THREAT_MODEL.md §5.5):
//   - kernel-mode dumpers (drivers) are invisible to user-mode
//     handle enumeration
//   - a sufficiently fast attacker can OpenProcess + ReadProcessMemory
//     + CloseHandle in the gap between two scans (~15 s default)
//   - false positives: AVs and overlays may briefly hold VM_READ
//     handles; we whitelist common system processes by image name

namespace AntiRpmGuard
{
    void start();    // call once at loader startup, after Sentinel::init
    void stop();     // call once at shutdown
}
