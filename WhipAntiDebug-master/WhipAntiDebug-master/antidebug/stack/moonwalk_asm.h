// ===== file: antidebug/stack/moonwalk_asm.h =====
//
// C declarations for the ASM moonwalk trampolines in moonwalk_stub.asm.
// Include this to use MoonwalkCall / MoonwalkStomp.
//
#ifndef ANTIDEBUG_MOONWALK_ASM_H
#define ANTIDEBUG_MOONWALK_ASM_H

#include "../core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// MoonwalkCall
//
// Calls fn(arg) while spoofing the top `n_decoys` return-address slots on
// the stack with entries from decoy_table[].
// Saves and restores all modified slots — safe to return through normally.
//
//   fn:           function to call; signature void fn(void* arg)
//   decoy_table:  array of n_decoys void* addresses (from ntdll .text ideally)
//   n_decoys:     number of frames to spoof (clamped to 8)
//   arg:          opaque argument forwarded to fn
//
// While fn() executes, any debugger call-stack view shows:
//   fn()
//   decoy_table[0]    (e.g. ntdll+0x1234)
//   decoy_table[1]    (e.g. ntdll+0x5678)
//   ...
// ---------------------------------------------------------------------------
void MoonwalkCall(
    void  (*fn)(void* arg),
    void** decoy_table,
    u32    n_decoys,
    void*  arg
);

// ---------------------------------------------------------------------------
// MoonwalkStomp
//
// Permanently overwrites the top `n_decoys` return-address slots with
// the provided decoys. No save/restore.
//
// CAUTION: only call this when you will NOT return through the spoofed frames
// (e.g., right before calling NtTerminateProcess).
//
//   decoy_table:  array of n_decoys void* addresses
//   n_decoys:     number of frames to stomp (clamped to 8)
// ---------------------------------------------------------------------------
void MoonwalkStomp(
    void** decoy_table,
    u32    n_decoys
);

#ifdef __cplusplus
}
#endif

#endif // ANTIDEBUG_MOONWALK_ASM_H
