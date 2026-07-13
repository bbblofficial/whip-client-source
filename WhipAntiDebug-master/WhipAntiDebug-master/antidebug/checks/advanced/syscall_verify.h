// ===== file: antidebug/checks/advanced/syscall_verify.h =====
//
// Direct-syscall debug state verification.
//
// ScyllaHide hooks ntdll stubs (NtQueryInformationProcess, NtGetContextThread,
// etc.) to return fake "not debugged" results. It CANNOT intercept a raw
// `syscall` instruction emitted by WhipSysCall — only the ntdll stub entry
// point is patched.
//
// These checks call the SAME NT functions through WhipSysCall's direct
// syscall path, bypassing every usermode hook layer.
//
//   1. ad_sv_debug_port_raw()    — ProcessDebugPort via direct syscall
//   2. ad_sv_debug_flags_raw()   — ProcessDebugFlags via direct syscall
//   3. ad_sv_debug_object_raw()  — ProcessDebugObjectHandle via direct syscall
//   4. ad_sv_context_dr_raw()    — DR register mismatch: direct vs hooked
//   5. ad_sv_stub_prologue_raw() — CRC of ntdll stub prologues (4C 8B D1 B8)
//   6. ad_sv_master()            — Weighted composite
//
#ifndef ANTIDEBUG_SYSCALL_VERIFY_H
#define ANTIDEBUG_SYSCALL_VERIFY_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../../stack/moonwalk.h"       // ad_ntdll_base()
#include "../runtime/write_watch.h"     // ad_pe_find_export()

#if defined(_MSC_VER)

// =========================================================================
// 1. ProcessDebugPort — direct syscall
// =========================================================================
//
// NtQueryInformationProcess(ProcessDebugPort = 7) returns a non-zero value
// when a debugger is attached. ScyllaHide's hook forces this to 0.
// Our direct syscall bypasses the hook entirely.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sv_debug_port_raw(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u64 debug_port = 0ULL;
    u32 ret_len = 0u;

    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        (u64)AD_PROCESS_DEBUG_PORT,     // InfoClass = 7
        &debug_port,
        (u64)sizeof(debug_port),
        &ret_len
    );

    // Clean process: debug_port == 0, STATUS_SUCCESS
    // Debugged:      debug_port != 0
    return (b32)(AD_NT_SUCCESS(st) && debug_port != 0ULL);
}

// =========================================================================
// 2. ProcessDebugFlags — direct syscall
// =========================================================================
//
// Class 31: returns 1 for clean processes (PROCESS_DEBUG_FLAGS == 1 means
// "do not debug"). Returns 0 when a debugger is attached. ScyllaHide
// forces this to 1 through the hook.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sv_debug_flags_raw(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u32 debug_flags = 1u;  // default to "clean"
    u32 ret_len = 0u;

    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        (u64)AD_PROCESS_DEBUG_FLAGS,    // InfoClass = 31
        &debug_flags,
        (u64)sizeof(debug_flags),
        &ret_len
    );

    // Clean: debug_flags == 1
    // Debugged: debug_flags == 0
    return (b32)(AD_NT_SUCCESS(st) && debug_flags == 0u);
}

// =========================================================================
// 3. ProcessDebugObjectHandle — direct syscall
// =========================================================================
//
// Class 30: if STATUS_SUCCESS → a debug object handle exists → debugger
// attached. Clean process: STATUS_PORT_NOT_SET (0xC0000353).
// ScyllaHide hooks this to always return STATUS_PORT_NOT_SET.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sv_debug_object_raw(void) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationProcess, 26);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u64 debug_object = 0ULL;
    u32 ret_len = 0u;

    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        (u64)AD_PROCESS_DEBUG_OBJECT_HANDLE,  // InfoClass = 30
        &debug_object,
        (u64)sizeof(debug_object),
        &ret_len
    );

    // STATUS_SUCCESS means debug object exists → debugger present
    return (b32)(AD_NT_SUCCESS(st));
}

// =========================================================================
// 4. DR register mismatch — direct vs hooked NtGetContextThread
// =========================================================================
//
// ScyllaHide hooks NtGetContextThread to zero DR0-DR3 in the returned
// CONTEXT. Our direct syscall returns the REAL values. If the program
// installed fake HW breakpoints (DR canary), the direct call shows them
// but the hooked call shows zeros → mismatch = ScyllaHide.
//
// Also detects if a debugger set its own DRs that ScyllaHide is hiding.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sv_context_dr_raw(void) {
    static u16 s_ssn_get = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_get, NtGetContextThread, 19);
    if (s_ssn_get == AD_SSN_FAILED) return 0;

    // ── Direct syscall: read real DR registers ─────────────────────────
    AD_ALIGN(16) AD_CONTEXT ctx_direct;
    AD_ZERO_BUF(&ctx_direct, sizeof(ctx_direct));
    ctx_direct.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;

    ad_ntstatus_t st1 = AD_SYSCALL2(s_ssn_get, AD_CURRENT_THREAD, &ctx_direct);
    if (!AD_NT_SUCCESS(st1)) return 0;

    // ── Hooked call: read through ntdll stub ────────────────────────────
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    typedef ad_ntstatus_t (*FN_NtGetContextThread)(void*, AD_CONTEXT*);
    FN_NtGetContextThread fn_get = (FN_NtGetContextThread)
        ad_pe_find_export((const u8*)ntdll, "NtGetContextThread");
    if (!fn_get) return 0;

    AD_ALIGN(16) AD_CONTEXT ctx_hooked;
    AD_ZERO_BUF(&ctx_hooked, sizeof(ctx_hooked));
    ctx_hooked.ContextFlags = AD_CONTEXT_DEBUG_REGISTERS;

    ad_ntstatus_t st2 = fn_get(AD_CURRENT_THREAD, &ctx_hooked);
    if (!AD_NT_SUCCESS(st2)) return 0;

    // ── Compare DR0-DR3: any mismatch = hook is hiding registers ────────
    b32 mismatch = 0;
    if (ctx_direct.Dr0 != ctx_hooked.Dr0) mismatch = 1;
    if (ctx_direct.Dr1 != ctx_hooked.Dr1) mismatch = 1;
    if (ctx_direct.Dr2 != ctx_hooked.Dr2) mismatch = 1;
    if (ctx_direct.Dr3 != ctx_hooked.Dr3) mismatch = 1;

    // Also: if direct syscall shows non-zero DRs that we didn't set,
    // a debugger placed them (even without ScyllaHide)
    u64 dr_sum = ctx_direct.Dr0 | ctx_direct.Dr1 | ctx_direct.Dr2 | ctx_direct.Dr3;
    AD_UNUSED(dr_sum);

    return mismatch;
}

// =========================================================================
// 5. ntdll stub prologue CRC — detect inline hooks on critical stubs
// =========================================================================
//
// Clean ntdll syscall stubs start with:
//   4C 8B D1   mov r10, rcx
//   B8 xx xx   mov eax, <SSN>
//
// ScyllaHide replaces with:
//   FF 25 00 00 00 00   jmp [rip+0]  (14-byte hook)
//   or E9 xx xx xx xx   jmp rel32
//
// We read the ACTUAL bytes via pointer (not NtReadVirtualMemory, since
// the memory mapping is the same) and verify the prologue.
// =========================================================================

// Stubs ScyllaHide always hooks
static const char* const AD_SV_CRITICAL_STUBS[] = {
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "NtClose",
    "NtGetContextThread",
    "NtSetContextThread",
    "NtQueryObject",
    "NtYieldExecution",
    "NtQuerySystemInformation",
    "NtContinue",
    "NtCreateThreadEx",
    (const char*)0
};

ANTIDEBUG_INLINE u32 ad_sv_stub_prologue_check(void) {
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0u;

    u32 hooked_count = 0u;
    u32 i;

    for (i = 0u; AD_SV_CRITICAL_STUBS[i]; i++) {
        const u8* stub = (const u8*)ad_pe_find_export(
            (const u8*)ntdll, AD_SV_CRITICAL_STUBS[i]);
        if (!stub) continue;

        // Read prologue bytes directly from memory
        volatile u8 b0 = stub[0];
        volatile u8 b1 = stub[1];
        volatile u8 b2 = stub[2];
        volatile u8 b3 = stub[3];

        // Clean prologue: 4C 8B D1 B8
        b32 clean = (b32)(b0 == 0x4Cu && b1 == 0x8Bu && b2 == 0xD1u && b3 == 0xB8u);

        // Hook signatures: FF 25 (indirect JMP), E9 (rel JMP), CC (INT3)
        b32 hooked = (b32)(
            (b0 == 0xFFu && b1 == 0x25u) ||  // ScyllaHide 14-byte hook
            (b0 == 0xE9u) ||                   // Frida/generic rel32 hook
            (b0 == 0xCCu) ||                   // INT3 breakpoint
            (!clean)                            // Any non-standard prologue
        );

        if (hooked) hooked_count++;
    }

    return hooked_count;
}

// =========================================================================
// 6. InstrumentationCallback detection
// =========================================================================
//
// ScyllaHide uses ProcessInstrumentationCallback (NtSetInformationProcess
// class 40) to intercept ALL syscall returns — even direct syscalls from
// WhipSysCall. The callback address is stored in PEB+0x110 on x64.
//
// A clean process has PEB.InstrumentationCallback == NULL. Any non-zero
// value means something (ScyllaHide, EDR, DBI) is intercepting syscalls.
// This is an UNFALSIFIABLE detection — no legitimate user-mode tool sets
// this in normal operation.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sv_instrumentation_callback(void) {
#if defined(_MSC_VER)
    volatile u8* peb = (volatile u8*)(u64)__readgsqword(0x60);
    if (!peb) return 0;

    // PEB+0x110 = InstrumentationCallback (x64)
    volatile u64 icb = *(volatile u64*)(peb + 0x110);

    return (b32)(icb != 0ULL);
#else
    return 0;
#endif
}

// =========================================================================
// 7. NtGlobalFlag direct read — ScyllaHide patches it to 0 but we can
//    check if the ORIGINAL value leaked through heap flags
// =========================================================================
//
// ScyllaHide patches PEB.NtGlobalFlag &= ~0x70 and PEB heap ForceFlags.
// But it does NOT patch the heaps that were ALREADY created by the loader
// before ScyllaHide's DLL injection. On some Windows versions, the first
// heap (PEB.ProcessHeap) retains the debug heap flags.
//
// ProcessHeap.Flags should be 0x02 (HEAP_GROWABLE) on clean process.
// Under debugger (before ScyllaHide patches): 0x50000062
// ScyllaHide patches ForceFlags but may leave Flags with residual bits.
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sv_heap_flags_residual(void) {
#if defined(_MSC_VER)
    volatile u8* peb = (volatile u8*)(u64)__readgsqword(0x60);
    if (!peb) return 0;

    // PEB+0x30 = ProcessHeap pointer
    volatile u8* heap = *(volatile u8**)(peb + 0x30);
    if (!heap) return 0;

    // HEAP.Flags at offset +0x70 (x64 Windows 10+)
    volatile u32 flags = *(volatile u32*)(heap + 0x70);

    // Clean: flags typically 0x02 (HEAP_GROWABLE) or 0x40000062 on some configs
    // Debug: flags has 0x50000062 (TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMS)
    // Only flag the specific debug bits: 0x20 (TAIL_CHECK), 0x10 (FREE_CHECK),
    // 0x40 (redundant but check explicitly)
    // Mask: 0x70 = the three debug heap flags
    u32 debug_bits = flags & 0x70u;
    // ForceFlags at +0x74 — ScyllaHide patches this too, but check anyway
    volatile u32 force_flags = *(volatile u32*)(heap + 0x74);
    u32 debug_force = force_flags & 0x70u;
    return (b32)(debug_bits == 0x70u || debug_force == 0x70u);
#else
    return 0;
#endif
}

// =========================================================================
// 8. NtContinue hook detection
// =========================================================================
//
// ScyllaHide hooks NtContinue to restore saved debug registers after
// KiUserExceptionDispatcher zeroed them. The NtContinue stub should
// start with 4C 8B D1 B8 (clean syscall pattern).
// =========================================================================
ANTIDEBUG_INLINE b32 ad_sv_ntcontinue_hooked(void) {
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;

    const u8* stub = (const u8*)ad_pe_find_export(
        (const u8*)ntdll, "NtContinue");
    if (!stub) return 0;

    volatile u8 b0 = stub[0];
    volatile u8 b1 = stub[1];
    volatile u8 b2 = stub[2];
    volatile u8 b3 = stub[3];

    // Clean syscall stub: 4C 8B D1 B8
    b32 clean = (b32)(b0 == 0x4Cu && b1 == 0x8Bu && b2 == 0xD1u && b3 == 0xB8u);
    if (clean) return 0;

    // Only flag KNOWN hook signatures, not any unusual prologue
    if (b0 == 0xE9u) return 1;                   // JMP rel32
    if (b0 == 0xFFu && b1 == 0x25u) return 1;    // JMP [rip+disp]
    if (b0 == 0x90u && b1 == 0xFFu) return 1;    // NOP + JMP

    // NtContinue on some Windows versions has different prologues
    // (e.g. 48 8B C4 on Win11) — don't flag those
    return 0;
}

// =========================================================================
// 9. Hook trampoline RWX memory detection
// =========================================================================
//
// ScyllaHide allocates RWX (PAGE_EXECUTE_READWRITE) memory for its hook
// trampolines. These trampolines contain the original function bytes +
// a JMP back. On a clean process, there should be ZERO MEM_PRIVATE
// regions with EXECUTE+WRITE rights. Each such region is suspicious.
//
// This overlaps with ad_private_exec_scan() but provides additional
// scoring specifically for ScyllaHide's trampoline pattern.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_sv_rwx_trampoline_count(void) {
    static u16 s_ssn_qvm = AD_SSN_UNRESOLVED;
    if (s_ssn_qvm == AD_SSN_UNRESOLVED) {
        // "NtQueryVirtualMemory"
        char name[] = { 'N','t','Q','u','e','r','y','V','i','r','t','u','a',
                        'l','M','e','m','o','r','y','\0' };
        s_ssn_qvm = whip_bridge_resolve(name);
        AD_WIPE_STR(name, sizeof(name));
    }
    if (s_ssn_qvm == AD_SSN_FAILED) return 0u;

    // Walk the VAD looking for MEM_PRIVATE + EXECUTE + WRITE
    u64 addr = 0x10000ULL;  // skip null page
    u32 rwx_count = 0u;
    u32 guard = 0u;

    while (addr < 0x7FFFFFFFE000ULL && guard < 4096u) {
        guard++;
        // MEMORY_BASIC_INFORMATION: 6 x u64 fields = 48 bytes
        u8 mbi[48];
        AD_ZERO_BUF(mbi, sizeof(mbi));
        u64 ret_len = 0ULL;

        ad_ntstatus_t st = (ad_ntstatus_t)(s64)SyscallStub(s_ssn_qvm,
            AD_CURRENT_PROCESS,
            (void*)addr,
            (void*)(u64)0u,    // MemoryBasicInformation
            (void*)mbi,
            (void*)(u64)sizeof(mbi),
            (void*)&ret_len,
            (void*)0, (void*)0, (void*)0, (void*)0, (void*)0
        );
        if (!AD_NT_SUCCESS(st)) break;

        u64 region_size = *(u64*)(mbi + 0x18);  // RegionSize
        u32 protect     = *(u32*)(mbi + 0x20);  // Protect
        u32 type        = *(u32*)(mbi + 0x28);  // Type

        // MEM_PRIVATE = 0x20000
        // PAGE_EXECUTE_READWRITE = 0x40
        // PAGE_EXECUTE_WRITECOPY = 0x80
        if (type == 0x20000u && (protect == 0x40u || protect == 0x80u)) {
            rwx_count++;
        }

        if (region_size == 0ULL) break;
        addr += region_size;
    }

    return rwx_count;
}

// =========================================================================
// MASTER — composite score from all verifications
// =========================================================================
ANTIDEBUG_INLINE u32 ad_sv_master(void) {
    u32 score = 0u;

#if AD_ENABLE_SYSCALL_VERIFY
    // Each check wrapped — some may crash on specific Windows versions
    // Gather ICB and stub hook state first — needed for gating decisions
    b32 v_icb = 0;
    u32 s_stubs = 0;
    __try { v_icb = ad_sv_instrumentation_callback(); } __except(1){}
    __try { s_stubs = ad_sv_stub_prologue_check();    } __except(1){}
    // InstrumentationCallback + stub hooks = ScyllaHide confirmed
    if (v_icb && s_stubs >= 2u) score += 20u;
    // Even without ICB correlation, each hooked stub is worth points
    score += s_stubs * 4u;

    // Heap flags residual disabled — heap layout varies across Win11
    // builds and the offset +0x70 is unreliable. The existing PEB
    // heap check in ad_run_hardened covers this better.
    // { b32 v = 0; __try { v = ad_sv_heap_flags_residual(); } __except(1){} if (v) score += 8u; }
    { b32 v = 0; __try { v = ad_sv_ntcontinue_hooked();        } __except(1){} if (v) score +=  9u; }

    // Direct syscall checks: ONLY when InstrumentationCallback is NULL.
    // Win11 sets ICB legitimately (AppCompat/telemetry) and it alters
    // syscall return values, causing false positives on clean processes.
    // When ICB is set AND stubs are hooked → ScyllaHide, scored above.
    if (!v_icb) {
        { b32 v = 0; __try { v = ad_sv_debug_port_raw();       } __except(1){} if (v) score += 15u; }
        { b32 v = 0; __try { v = ad_sv_debug_flags_raw();      } __except(1){} if (v) score += 12u; }
        { b32 v = 0; __try { v = ad_sv_debug_object_raw();     } __except(1){} if (v) score += 12u; }
        { b32 v = 0; __try { v = ad_sv_context_dr_raw();       } __except(1){} if (v) score += 10u; }
    }
#endif

    return score;
}

#else  // Non-MSVC stubs

ANTIDEBUG_INLINE b32 ad_sv_debug_port_raw(void)          { return 0; }
ANTIDEBUG_INLINE b32 ad_sv_debug_flags_raw(void)         { return 0; }
ANTIDEBUG_INLINE b32 ad_sv_debug_object_raw(void)        { return 0; }
ANTIDEBUG_INLINE b32 ad_sv_context_dr_raw(void)          { return 0; }
ANTIDEBUG_INLINE u32 ad_sv_stub_prologue_check(void)     { return 0u; }
ANTIDEBUG_INLINE b32 ad_sv_instrumentation_callback(void) { return 0; }
ANTIDEBUG_INLINE b32 ad_sv_heap_flags_residual(void)     { return 0; }
ANTIDEBUG_INLINE b32 ad_sv_ntcontinue_hooked(void)       { return 0; }
ANTIDEBUG_INLINE u32 ad_sv_rwx_trampoline_count(void)    { return 0u; }
ANTIDEBUG_INLINE u32 ad_sv_master(void)                  { return 0u; }

#endif // _MSC_VER

#endif // ANTIDEBUG_SYSCALL_VERIFY_H
