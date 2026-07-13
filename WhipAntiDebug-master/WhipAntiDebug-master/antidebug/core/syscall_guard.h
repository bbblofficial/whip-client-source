// ===== file: antidebug/core/syscall_guard.h =====
//
// SyscallStub prologue integrity guard.
//
// Attack vector: a single JMP (0xE9) or INT3 (0xCC) patched at the start of
// SyscallStub disables every direct syscall in the framework. This module
// snapshots the first 16 bytes of SyscallStub at init time (CRC32) and
// verifies them on each check iteration, catching inline hooks, detours,
// and breakpoints.
//
#ifndef ANTIDEBUG_SYSCALL_GUARD_H
#define ANTIDEBUG_SYSCALL_GUARD_H

#include "types.h"
#include "macros.h"
#include "syscall_bridge.h"

// ---------------------------------------------------------------------------
// CRC32 (polynomial 0xEDB88320, same bit-reversal as zlib/pkzip)
// ---------------------------------------------------------------------------
#define AD_SYSCALL_GUARD_LEN   16u

ANTIDEBUG_INLINE u32 ad_crc32_bytes(const u8* data, u32 len) {
    u32 crc = 0xFFFFFFFFu;
    u32 i, bit;
    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (bit = 0; bit < 8u; bit++) {
            if (crc & 1u)
                crc = (crc >> 1) ^ 0xEDB88320u;
            else
                crc >>= 1;
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

// ---------------------------------------------------------------------------
// Global snapshot — stored at init, verified each iteration
// ---------------------------------------------------------------------------
static volatile u32 g_syscall_stub_crc = 0;
static volatile b32 g_syscall_guard_ready = 0;

// ---------------------------------------------------------------------------
// ad_syscall_guard_init — call once after whip_bridge_init().
// Snapshots CRC32 of SyscallStub prologue.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_syscall_guard_init(void) {
    const u8* stub = (const u8*)(void*)&SyscallStub;
    g_syscall_stub_crc = ad_crc32_bytes(stub, AD_SYSCALL_GUARD_LEN);
    AD_BARRIER();
    g_syscall_guard_ready = 1;
}

// ---------------------------------------------------------------------------
// ad_syscall_guard_verify — returns 1 if SyscallStub is tampered.
//
// Two independent checks:
//   1. CRC32 mismatch against init-time snapshot.
//   2. First byte is a known hook opcode (0xE9 JMP rel32, 0xFF JMP/CALL
//      indirect, 0xCC INT3 breakpoint).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_syscall_guard_verify(void) {
    if (!g_syscall_guard_ready) return 0;

    const u8* stub = (const u8*)(void*)&SyscallStub;

    // Check 1: hook-signature opcodes at entry point
    u8 first = stub[0];
    if (first == 0xE9u ||   // JMP rel32
        first == 0xFFu ||   // JMP/CALL indirect (modrm variants)
        first == 0xCCu) {   // INT3 software breakpoint
        return 1;
    }

    // Check 2: CRC32 mismatch
    u32 current_crc = ad_crc32_bytes(stub, AD_SYSCALL_GUARD_LEN);
    if (current_crc != g_syscall_stub_crc) {
        return 1;
    }

    return 0;
}

#endif // ANTIDEBUG_SYSCALL_GUARD_H
