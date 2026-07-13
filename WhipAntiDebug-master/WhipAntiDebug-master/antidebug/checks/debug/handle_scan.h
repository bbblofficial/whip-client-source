// ===== file: antidebug/checks/debug/handle_scan.h =====
//
// Detect open handles to our process from foreign processes.
//
// A debugger MUST hold an open handle to its target process. This handle has
// access rights like PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME.
// We enumerate all system handles via NtQuerySystemInformation(64) and count
// handles targeting our process object that come from outside our own PID.
//
// Algorithm:
//   1. Get our PID from TEB.ClientId.UniqueProcess (GS:0x040)
//   2. Open a PROCESS_QUERY_LIMITED_INFORMATION handle to ourselves
//   3. Enumerate all system handles (SystemExtendedHandleInformation = 64)
//   4. Find our entry [OurPID + our handle value] → get our kernel Object ptr
//   5. Count entries where Object == ours && PID != ours && PID != System
//      && GrantedAccess has suspicious debug-related flags
//   6. Suspicious: (VM_READ|VM_WRITE|SUSPEND_RESUME) all set simultaneously
//
// Notes:
//   - SystemExtendedHandleInformation (64) gives properly aligned u64 fields on x64
//   - Allocates a heap buffer via NtAllocateVirtualMemory; retries up to 3× if
//     STATUS_INFO_LENGTH_MISMATCH is returned
//   - Returns 1 if any foreign process holds a debugger-class handle to us
//
#ifndef ANTIDEBUG_HANDLE_SCAN_H
#define ANTIDEBUG_HANDLE_SCAN_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// SystemExtendedHandleInformation structures (class 64, x64 layout)
// ---------------------------------------------------------------------------
typedef struct {
    void* Object;                   // +0  kernel object pointer (8 bytes)
    u64   UniqueProcessId;          // +8
    u64   HandleValue;              // +16
    u32   GrantedAccess;            // +24
    u16   CreatorBackTraceIndex;    // +28
    u16   ObjectTypeIndex;          // +30
    u32   HandleAttributes;         // +32
    u32   _reserved;                // +36
    // sizeof = 40 bytes
} AD_SYSTEM_HANDLE_EX;

typedef struct {
    u64               NumberOfHandles;  // +0
    u64               Reserved;         // +8
    AD_SYSTEM_HANDLE_EX Handles[1];     // +16
} AD_SYSTEM_HANDLE_INFO_EX;

// Access right masks indicative of debugger / memory scanner
#define AD_HS_VM_READ      0x00000010UL
#define AD_HS_VM_WRITE     0x00000020UL
#define AD_HS_SUSPEND      0x00000800UL   // PROCESS_SUSPEND_RESUME
// Presence of all three simultaneously = debugger-class access
#define AD_HS_DEBUG_MASK   (AD_HS_VM_READ | AD_HS_VM_WRITE | AD_HS_SUSPEND)

#define AD_STATUS_INFO_LEN_MISMATCH  0xC0000004UL

ANTIDEBUG_INLINE b32 ad_handle_scan(void) {
    // ── SSN resolution ───────────────────────────────────────────────────
    static u16 s_ssn_qsi  = AD_SSN_UNRESOLVED;  // NtQuerySystemInformation
    static u16 s_ssn_op   = AD_SSN_UNRESOLVED;  // NtOpenProcess
    static u16 s_ssn_cl   = AD_SSN_UNRESOLVED;  // NtClose
    static u16 s_ssn_alloc = AD_SSN_UNRESOLVED; // NtAllocateVirtualMemory
    static u16 s_ssn_free  = AD_SSN_UNRESOLVED; // NtFreeVirtualMemory

    AD_RESOLVE_SSN_ENC(s_ssn_qsi,   NtQuerySystemInformation, 25);
    AD_RESOLVE_SSN_ENC(s_ssn_op,    NtOpenProcess,            14);
    AD_RESOLVE_SSN_ENC(s_ssn_cl,    NtClose,                   8);
    AD_RESOLVE_SSN_ENC(s_ssn_alloc, NtAllocateVirtualMemory,  24);
    AD_RESOLVE_SSN_ENC(s_ssn_free,  NtFreeVirtualMemory,      20);

    if (s_ssn_qsi   == AD_SSN_FAILED) return 0;
    if (s_ssn_op    == AD_SSN_FAILED) return 0;
    if (s_ssn_cl    == AD_SSN_FAILED) return 0;
    if (s_ssn_alloc == AD_SSN_FAILED) return 0;
    if (s_ssn_free  == AD_SSN_FAILED) return 0;

    // ── Get our PID from TEB.ClientId ───────────────────────────────────
    u32 our_pid = (u32)(u64)__readgsqword(0x040);

    // ── Open ourselves to obtain a real handle value ─────────────────────
    AD_CLIENT_ID  our_cid;
    our_cid.UniqueProcess = (void*)(u64)our_pid;
    our_cid.UniqueThread  = (void*)0;

    AD_OBJECT_ATTRIBUTES oa;
    AD_ZERO_BUF(&oa, sizeof(oa));
    oa.Length = (u32)sizeof(oa);

    void* self_handle = (void*)0;
    ad_ntstatus_t st = AD_SYSCALL4(s_ssn_op,
        &self_handle,
        (u64)0x1000,   // PROCESS_QUERY_LIMITED_INFORMATION
        &oa,
        &our_cid);
    if (!AD_NT_SUCCESS(st) || !self_handle) return 0;

    u64 self_handle_val = (u64)self_handle;

    // ── Allocate buffer for system handle table ──────────────────────────
    void*  buf      = (void*)0;
    u64    buf_size = 0x200000ULL;   // start at 2 MB
    u32    retries  = 0u;
    b32    filled   = 0;

    while (retries < 4u) {
        void* tmp    = (void*)0;
        u64   tmp_sz = buf_size;
        st = AD_SYSCALL6(s_ssn_alloc,
            AD_CURRENT_PROCESS,
            &tmp,
            (u64)0,
            &tmp_sz,
            (u64)(0x1000UL | 0x2000UL),  // MEM_COMMIT | MEM_RESERVE
            (u64)0x04UL);                 // PAGE_READWRITE
        if (!AD_NT_SUCCESS(st)) {
            AD_SYSCALL2(s_ssn_cl, self_handle, (u64)0);
            return 0;
        }
        buf = tmp;

        u32 needed = 0u;
        st = AD_SYSCALL4(s_ssn_qsi,
            (u64)64,   // SystemExtendedHandleInformation
            buf,
            (u64)buf_size,
            &needed);

        if (AD_NT_SUCCESS(st)) { filled = 1; break; }

        // Free and retry with larger buffer
        void* free_base = buf;
        u64   free_size = 0ULL;
        AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &free_base, &free_size, (u64)0x8000UL);
        buf = (void*)0;

        if (st == (ad_ntstatus_t)AD_STATUS_INFO_LEN_MISMATCH) {
            buf_size = (needed > 0u) ? ((u64)needed + 0x10000ULL) : (buf_size * 2ULL);
        } else {
            break;
        }
        retries++;
    }

    if (!filled || !buf) {
        AD_SYSCALL2(s_ssn_cl, self_handle, (u64)0);
        return 0;
    }

    // ── Find our process kernel object pointer ───────────────────────────
    const AD_SYSTEM_HANDLE_INFO_EX* info = (const AD_SYSTEM_HANDLE_INFO_EX*)buf;
    u64 count = info->NumberOfHandles;
    const AD_SYSTEM_HANDLE_EX* entries =
        (const AD_SYSTEM_HANDLE_EX*)((const u8*)buf + 16u);

    void* our_obj       = (void*)0;
    u16   our_type_idx  = 0u;
    b32   entry_found   = 0;   // set when {our_pid, self_handle_val} is in the table
    u64   i;
    for (i = 0u; i < count; i++) {
        const AD_SYSTEM_HANDLE_EX* e = &entries[i];
        if (e->UniqueProcessId == (u64)our_pid &&
            e->HandleValue     == self_handle_val) {
            our_obj      = e->Object;         // NULL on Win11 (OS zeroes kernel ptrs)
            our_type_idx = e->ObjectTypeIndex; // Process type index (stable per boot)
            entry_found  = 1;
            break;
        }
    }

    // Close our temporary self-handle
    AD_SYSCALL2(s_ssn_cl, self_handle, (u64)0);

    // ── Detection 1: missing entry = handle table tampered ───────────────
    // NtOpenProcess succeeded → handle exists in the kernel.
    // If our {pid, handle} entry is absent from SystemExtendedHandleInformation,
    // a tool (ScyllaHide kernel driver / Handle Table Guard) filtered it out.
    b32 found = (b32)(!entry_found);

    // ── Detection 2: foreign debug-class handle to our object ────────────
    // Object-based matching works on pre-Win11 where the kernel pointer is
    // non-zero; silently skipped when our_obj is zero (Win11 + elevated).
    if (our_obj) {
        for (i = 0u; i < count; i++) {
            const AD_SYSTEM_HANDLE_EX* e = &entries[i];
            if (e->Object != our_obj) continue;
            if (e->UniqueProcessId == (u64)our_pid) continue;
            if (e->UniqueProcessId == 0u) continue;
            if (e->UniqueProcessId == 4u) continue;

            if ((e->GrantedAccess & AD_HS_DEBUG_MASK) == AD_HS_DEBUG_MASK) {
                found = 1;
                break;
            }
        }
    }

    // ── Detection 3 (Win11 fallback): DISABLED ────────────────────────────
    // ObjectTypeIndex-based scan matches ANY foreign PID with debug-class
    // Process handles — not specifically handles to OUR process (Object is
    // zeroed). This produces false positives on busy systems where services
    // hold many process handles. Keeping the code for reference; needs a
    // per-handle NtQueryObject fallback to filter by target PID.
    // ── Detection 3 (Win11): TypeIndex scan + DebugPort cross-check ────
    // On Win11, Object is zeroed → can't match handles to our process.
    // We check: (a) foreign PID holds 3+ debug-class Process handles,
    // AND (b) our process has an active DebugPort (confirms WE are the target).
    // Without (b), the handles could target any process → false positive.
    if (!found && !our_obj && entry_found && our_type_idx != 0u) {
        // Cross-check: confirm WE are being debugged via DebugPort
        static u16 s_ssn_qip_hs = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_ssn_qip_hs, NtQueryInformationProcess, 26);
        b32 we_are_debugged = 0;
        if (s_ssn_qip_hs != AD_SSN_FAILED) {
            u64 dbg_port = 0; u32 rl = 0;
            ad_ntstatus_t qst = AD_SYSCALL5(s_ssn_qip_hs,
                AD_CURRENT_PROCESS, (u64)7, &dbg_port,
                (u64)sizeof(dbg_port), &rl);
            if (AD_NT_SUCCESS(qst) && dbg_port != 0) we_are_debugged = 1;
            // Also try ProcessDebugObjectHandle (class 30)
            if (!we_are_debugged) {
                u64 dbg_obj = 0;
                qst = AD_SYSCALL5(s_ssn_qip_hs,
                    AD_CURRENT_PROCESS, (u64)30, &dbg_obj,
                    (u64)sizeof(dbg_obj), &rl);
                if (AD_NT_SUCCESS(qst) && dbg_obj != 0) we_are_debugged = 1;
            }
        }
        if (we_are_debugged) {
            for (i = 0u; i < count; i++) {
                const AD_SYSTEM_HANDLE_EX* e = &entries[i];
                if (e->ObjectTypeIndex != our_type_idx) continue;
                if (e->UniqueProcessId == (u64)our_pid) continue;
                if (e->UniqueProcessId == 0u) continue;
                if (e->UniqueProcessId == 4u) continue;
                if ((e->GrantedAccess & AD_HS_DEBUG_MASK) == AD_HS_DEBUG_MASK) {
                    u64 foreign_pid = e->UniqueProcessId;
                    u32 dbg_count = 0u;
                    u64 j;
                    for (j = 0u; j < count && dbg_count < 3u; j++) {
                        const AD_SYSTEM_HANDLE_EX* f = &entries[j];
                        if (f->UniqueProcessId != foreign_pid) continue;
                        if (f->ObjectTypeIndex != our_type_idx) continue;
                        if ((f->GrantedAccess & AD_HS_DEBUG_MASK) == AD_HS_DEBUG_MASK)
                            dbg_count++;
                    }
                    if (dbg_count >= 3u) {
                        found = 1;
                        break;
                    }
                }
            }
        }
    }

    // ── Free buffer ──────────────────────────────────────────────────────
    {
        void* free_base = buf;
        u64   free_size = 0ULL;
        AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &free_base, &free_size, (u64)0x8000UL);
    }

    return found;
}

#else
ANTIDEBUG_INLINE b32 ad_handle_scan(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_HANDLE_SCAN_H