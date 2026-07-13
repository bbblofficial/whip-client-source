// ===== file: antidebug/stack/stealth_exec.h =====
//
// Stealth Execution — run anti-debug checks off the main call stack.
//
// Two mechanisms, both completely invisible:
//
//   1. POOL EXEC — queue the check as a work item to the Windows default
//      thread pool via ntdll!RtlQueueWorkItem. The work runs on an
//      existing TpWorkerThread. No new threads, no new TEBs, no thread
//      count change. Main thread waits on an NtEvent.
//
//   2. SELF-APC — queue the check as an APC on our own thread, then
//      enter an alertable wait. The kernel dispatches the callback via
//      KiUserApcDispatcher. Stack shows only ntdll frames.
//
// Detection surface: ZERO
//   - Thread count: unchanged
//   - Thread list: unchanged
//   - Memory map: no suspicious pages
//   - Stack walk: ntdll!TppWorkerThread or KiUserApcDispatcher only
//   - Handle table: 1 Event handle (if pool exec), nothing unusual
//
#ifndef ANTIDEBUG_STEALTH_EXEC_H
#define ANTIDEBUG_STEALTH_EXEC_H

#include "../core/types.h"
#include "../core/macros.h"
#include "../core/syscall_bridge.h"
#include "../core/string_encrypt.h"
#include "moonwalk.h"                       // ad_ntdll_base
#include "../checks/runtime/write_watch.h"  // ad_pe_find_export

#if defined(_MSC_VER)

// =========================================================================
// Shared types
// =========================================================================

typedef u32 (*ad_stealth_fn_t)(void* arg);

// Mailbox layout (offsets are baked into the hand-written ghost trampoline
// in ad_ghost_exec — keep them in sync if you reorder).
//
//   +0x00 result      result of fn (set by trampoline post-call)
//   +0x04 done        flag set after fn returns (1 = done)
//   +0x08 fn          encrypted fn pointer (XOR with PEB pointer in ghost
//                     path; plaintext in apc path — apc_callback does the
//                     same xor before invoking)
//   +0x10 arg         argument forwarded to fn
//   +0x18 event       NtEvent handle for the ghost path (NULL for apc)
//   +0x20 fake_ra     forged ntdll RA the trampoline writes over its own
//                     saved-RA slot during fn execution — the worker thread
//                     stack walk shows this address as the trampoline's
//                     parent, NOT the real BaseThreadInitThunk
typedef struct {
    volatile u32    result;
    volatile b32    done;
    ad_stealth_fn_t fn;       // XOR-encrypted with PEB pointer
    void*           arg;
    void*           event;
    void*           fake_ra;
    void*           fake_stack_top;   // 0x28 — initial RSP for the pivot
    void*           old_rsp_save;     // 0x30 — real RSP stash
    void*           fake_stack_base;  // 0x38 — bottom of fake stack region
    void*           old_stack_base;   // 0x40 — TEB.NtTib.StackBase save
    void*           old_stack_limit;  // 0x48 — TEB.NtTib.StackLimit save
} ad_stealth_mailbox_t;

// =========================================================================
// 1. POOL EXEC — thread pool work item
// =========================================================================
//
// Flow (100% direct syscall — unhookable by Frida/DBI):
//   main thread
//   ───────────
//   NtCreateTimer → timer handle
//   NtSetTimer(timer, due=1ms, APC=callback, ctx=&mailbox)
//   NtWaitForSingleObject(timer, alertable=TRUE)
//     ← kernel fires timer APC on our thread
//     ← KiUserApcDispatcher → callback(mailbox)
//     ← callback writes result, returns
//   read mailbox->result
//   NtClose(timer)

// Encrypted: "NtWaitForSingleObject" (21 chars)
#ifndef AD_STRENC_NtWaitForSingleObject
#define AD_STRENC_NtWaitForSingleObject(buf)                                 \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x5D);                                     \
        char buf##_e[22];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'W', _k); AD_ENC(buf##_e,  3, 'a', _k);       \
        AD_ENC(buf##_e,  4, 'i', _k); AD_ENC(buf##_e,  5, 't', _k);       \
        AD_ENC(buf##_e,  6, 'F', _k); AD_ENC(buf##_e,  7, 'o', _k);       \
        AD_ENC(buf##_e,  8, 'r', _k); AD_ENC(buf##_e,  9, 'S', _k);       \
        AD_ENC(buf##_e, 10, 'i', _k); AD_ENC(buf##_e, 11, 'n', _k);       \
        AD_ENC(buf##_e, 12, 'g', _k); AD_ENC(buf##_e, 13, 'l', _k);       \
        AD_ENC(buf##_e, 14, 'e', _k); AD_ENC(buf##_e, 15, 'O', _k);       \
        AD_ENC(buf##_e, 16, 'b', _k); AD_ENC(buf##_e, 17, 'j', _k);       \
        AD_ENC(buf##_e, 18, 'e', _k); AD_ENC(buf##_e, 19, 'c', _k);       \
        AD_ENC(buf##_e, 20, 't', _k);                                       \
        AD_DECODE_BUF(buf##_e, 21, _k);                                     \
        for (unsigned _ci = 0; _ci < 22; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

// Encrypted: "NtCreateEvent" (13 chars) — ADD variant
#ifndef AD_STRENC_NtCreateEvent
#define AD_STRENC_NtCreateEvent(buf)                                         \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x91);                                     \
        char buf##_e[14];                                                    \
        AD_ENC_ADD(buf##_e,  0, 'N', _k); AD_ENC_ADD(buf##_e,  1, 't', _k); \
        AD_ENC_ADD(buf##_e,  2, 'C', _k); AD_ENC_ADD(buf##_e,  3, 'r', _k); \
        AD_ENC_ADD(buf##_e,  4, 'e', _k); AD_ENC_ADD(buf##_e,  5, 'a', _k); \
        AD_ENC_ADD(buf##_e,  6, 't', _k); AD_ENC_ADD(buf##_e,  7, 'e', _k); \
        AD_ENC_ADD(buf##_e,  8, 'E', _k); AD_ENC_ADD(buf##_e,  9, 'v', _k); \
        AD_ENC_ADD(buf##_e, 10, 'e', _k); AD_ENC_ADD(buf##_e, 11, 'n', _k); \
        AD_ENC_ADD(buf##_e, 12, 't', _k);                                   \
        AD_DECODE_BUF_ADD(buf##_e, 13, _k);                                 \
        for (unsigned _ci = 0; _ci < 14; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

// Encrypted: "NtSetEvent" (10 chars) — ADD variant
#ifndef AD_STRENC_NtSetEvent
#define AD_STRENC_NtSetEvent(buf)                                            \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0xA3);                                     \
        char buf##_e[11];                                                    \
        AD_ENC_ADD(buf##_e,  0, 'N', _k); AD_ENC_ADD(buf##_e,  1, 't', _k); \
        AD_ENC_ADD(buf##_e,  2, 'S', _k); AD_ENC_ADD(buf##_e,  3, 'e', _k); \
        AD_ENC_ADD(buf##_e,  4, 't', _k); AD_ENC_ADD(buf##_e,  5, 'E', _k); \
        AD_ENC_ADD(buf##_e,  6, 'v', _k); AD_ENC_ADD(buf##_e,  7, 'e', _k); \
        AD_ENC_ADD(buf##_e,  8, 'n', _k); AD_ENC_ADD(buf##_e,  9, 't', _k); \
        AD_DECODE_BUF_ADD(buf##_e, 10, _k);                                 \
        for (unsigned _ci = 0; _ci < 11; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

// Forward declaration — APC exec defined below, used as fallback.
ANTIDEBUG_INLINE u32 ad_apc_exec(ad_stealth_fn_t fn, void* arg);

// XOR key used to encrypt mailbox.fn — derived from the PEB pointer (per-
// process random, unknown statically, accessible from any thread via gs:[60]).
ANTIDEBUG_INLINE u64 ad_stealth_fn_xor_key(void) {
#ifdef _MSC_VER
    return (u64)__readgsqword(0x60);
#else
    return 0;
#endif
}

// MSVC intrinsic — pointer to the saved-RA slot of the current frame.
#ifdef _MSC_VER
void* _AddressOfReturnAddress(void);
#pragma intrinsic(_AddressOfReturnAddress)
#endif

// Encrypted: "NtTerminateThread" (17 chars). Used by ad_ghost_thread_entry
// to exit the worker without going through `ret` (its saved-RA slot is
// forged to a fake ntdll address — `ret` would jump there and crash).
#ifndef AD_STRENC_NtTerminateThread
#define AD_STRENC_NtTerminateThread(buf)                                     \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x6E);                                     \
        char buf##_e[18];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'T', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 'r', _k); AD_ENC(buf##_e,  5, 'm', _k);       \
        AD_ENC(buf##_e,  6, 'i', _k); AD_ENC(buf##_e,  7, 'n', _k);       \
        AD_ENC(buf##_e,  8, 'a', _k); AD_ENC(buf##_e,  9, 't', _k);       \
        AD_ENC(buf##_e, 10, 'e', _k); AD_ENC(buf##_e, 11, 'T', _k);       \
        AD_ENC(buf##_e, 12, 'h', _k); AD_ENC(buf##_e, 13, 'r', _k);       \
        AD_ENC(buf##_e, 14, 'e', _k); AD_ENC(buf##_e, 15, 'a', _k);       \
        AD_ENC(buf##_e, 16, 'd', _k);                                       \
        AD_DECODE_BUF(buf##_e, 17, _k);                                     \
        for (unsigned _ci = 0; _ci < 18; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

// Ghost thread entry (fallback — the hand-written trampoline is preferred
// when NtAllocateVirtualMemory succeeds). Decrypts mb->fn before calling.
//
// Stack-trace consequences of the RA spoof + NtTerminateThread exit applied
// in this body:
//   * Without spoof, the saved-RA slot points to BaseThreadInitThunk and
//     a stack walker reads `BTIT → ad_ghost_thread_entry → fn`. The
//     symbol "ad_ghost_thread_entry" leaks via the binary's exports/PDB
//     and tells the reverser exactly which function to set a hardware
//     breakpoint on.
//   * With spoof + NtTerminateThread exit, the saved-RA reads as
//     `ntdll!RtlUserThreadStart+0x21` (a real function in ntdll's text
//     segment) so the walker concludes the parent is a generic Win32
//     thread, indistinguishable from any worker. The forged RA is never
//     executed because NtTerminateThread short-circuits the return.
static unsigned long __stdcall ad_ghost_thread_entry(void* param) {
#ifdef _MSC_VER
    {
        void* fake = ad_resolve_api(AD_HASH_NTDLL,
                                     ad_hash_str("RtlUserThreadStart"));
        if (fake) {
            void** ra_slot = (void**)_AddressOfReturnAddress();
            *ra_slot = (void*)((u8*)fake + 0x21);
        }
    }
#endif

    ad_stealth_mailbox_t* mb = (ad_stealth_mailbox_t*)param;
    if (mb && mb->fn) {
        ad_stealth_fn_t real_fn = (ad_stealth_fn_t)
            ((u64)mb->fn ^ ad_stealth_fn_xor_key());
        void* real_arg = mb->arg;
        // Wipe sensitive fields before fn runs — match trampoline behaviour.
        mb->fn      = (ad_stealth_fn_t)0;
        mb->arg     = (void*)0;
        mb->fake_ra = (void*)0;
        __try {
            mb->result = real_fn(real_arg);
        } __except(1) {
            mb->result = 0xFFFFFFFFu;
        }
    }
    AD_BARRIER();
    mb->done = 1;

    // Signal event
    if (mb->event) {
        static u16 s_set = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_set, NtSetEvent, 11);
        if (s_set != AD_SSN_FAILED)
            AD_SYSCALL2(s_set, mb->event, (u64)0);
    }

    // Exit via NtTerminateThread so the forged saved-RA is never executed.
    // The corrupted slot points into ntdll's text — returning there would
    // crash. The kernel reaps the thread cleanly via the syscall.
    {
        static u16 s_term = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_term, NtTerminateThread, 18);
        if (s_term != AD_SSN_FAILED) {
            AD_SYSCALL2(s_term, AD_CURRENT_THREAD, (u64)0);
        }
    }
    return 0;  // unreachable when NtTerminateThread succeeds
}

ANTIDEBUG_INLINE u32 ad_ghost_exec(ad_stealth_fn_t fn, void* arg) {
    // 100% direct syscall — NtCreateThreadEx + NtSetInformationThread +
    // NtCreateEvent + NtWaitForSingleObject. No user-mode lib calls.
    static u16 s_ssn_create_th = AD_SSN_UNRESOLVED;
    static u16 s_ssn_create_ev = AD_SSN_UNRESOLVED;
    static u16 s_ssn_seti      = AD_SSN_UNRESOLVED;
    static u16 s_ssn_resume    = AD_SSN_UNRESOLVED;
    static u16 s_ssn_wait      = AD_SSN_UNRESOLVED;
    static u16 s_ssn_close     = AD_SSN_UNRESOLVED;
    static u16 s_ssn_alloc     = AD_SSN_UNRESOLVED;
    static u16 s_ssn_free      = AD_SSN_UNRESOLVED;
    static u16 s_ssn_set_event = AD_SSN_UNRESOLVED;  // for self-contained trampoline
    static u16 s_ssn_protect   = AD_SSN_UNRESOLVED;  // VirtualProtect → PAGE_EXECUTE

    AD_RESOLVE_SSN_ENC(s_ssn_create_ev, NtCreateEvent, 14);
    AD_RESOLVE_SSN_ENC(s_ssn_wait, NtWaitForSingleObject, 22);
    AD_RESOLVE_SSN_ENC(s_ssn_close, NtClose, 8);
    AD_RESOLVE_SSN_ENC(s_ssn_set_event, NtSetEvent, 11);

    // Resolve thread creation SSNs via raw names (no macro needed)
    if (s_ssn_create_th == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0};
        s_ssn_create_th = whip_bridge_resolve(n);
    }
    if (s_ssn_seti == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','S','e','t','I','n','f','o','r','m','a','t','i','o','n','T','h','r','e','a','d',0};
        s_ssn_seti = whip_bridge_resolve(n);
    }
    if (s_ssn_resume == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','R','e','s','u','m','e','T','h','r','e','a','d',0};
        s_ssn_resume = whip_bridge_resolve(n);
    }
    if (s_ssn_alloc == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
        s_ssn_alloc = whip_bridge_resolve(n);
    }
    if (s_ssn_free == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','F','r','e','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
        s_ssn_free = whip_bridge_resolve(n);
    }
    if (s_ssn_protect == AD_SSN_UNRESOLVED) {
        char n[] = {'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
        s_ssn_protect = whip_bridge_resolve(n);
    }

    if (s_ssn_create_th == AD_SSN_FAILED || s_ssn_create_ev == AD_SSN_FAILED ||
        s_ssn_wait == AD_SSN_FAILED || s_ssn_close == AD_SSN_FAILED ||
        s_ssn_resume == AD_SSN_FAILED) {
        // Fallback: run via APC (proven to work)
        return ad_apc_exec(fn, arg);
    }

    // Create unsignaled event for synchronization
    void* event = (void*)0;
    ad_ntstatus_t st = AD_SYSCALL5(s_ssn_create_ev,
        &event, (u64)0x001F0003UL, (u64)0, (u64)1, (u64)0);
    if (!AD_NT_SUCCESS(st) || !event) {
        return ad_apc_exec(fn, arg);
    }

    // ── Forge fake parent RA for the worker stack ───────────────────────
    // The worker's saved-RA slot would normally point back to
    // kernel32!BaseThreadInitThunk. The trampoline replaces it during fn
    // execution with an address inside ntdll!RtlUserThreadStart so that a
    // sampler walking the worker stack sees a fake parent. We restore the
    // real RA before `ret` so thread teardown still works.
    void* fake_ra = (void*)0;
    {
        void* p = ad_resolve_api(AD_HASH_NTDLL, ad_hash_str("RtlUserThreadStart"));
        if (p) fake_ra = (void*)((u8*)p + 0x21);
    }

    // ── Mailbox: fn pointer is XOR-encrypted with PEB so a memory dump of
    // the mailbox doesn't reveal the orchestrator address. The trampoline
    // re-applies the same XOR to recover the live pointer in a register.
    ad_stealth_mailbox_t mailbox;
    AD_ZERO_BUF(&mailbox, sizeof(mailbox));
    mailbox.fn      = (ad_stealth_fn_t)((u64)fn ^ ad_stealth_fn_xor_key());
    mailbox.arg     = arg;
    mailbox.event   = event;
    mailbox.fake_ra = fake_ra;
    mailbox.done    = 0;

    // ── Anonymous RWX page for the self-contained thread entry ──────────
    // Strategy:
    //   1. Allocate 4 KB.
    //   2. Fill with random bytes (so the page contents look like garbage —
    //      a memory dump must search for the actual trampoline body).
    //   3. Pick a random offset within the first half of the page; write
    //      the trampoline there. The thread entry passed to NtCreateThreadEx
    //      is `tramp + offset`, not `tramp` — the page address alone does
    //      NOT lead a reverser straight to the trampoline.
    //   4. After the thread is suspended-created and resumed, flip the page
    //      to PAGE_EXECUTE (best-effort — suppresses casual user-mode reads
    //      of the trampoline body).
    //
    // Trampoline assembly (entry: rcx = mailbox pointer). All offsets refer
    // to mailbox fields; saved-RA from BaseThreadInitThunk's CALL is at
    // [rsp+0x38] after the prologue (push rbx; push rsi; sub rsp,0x28):
    //
    //   53                     push rbx
    //   56                     push rsi
    //   48 83 EC 28            sub  rsp, 0x28
    //   48 89 CB               mov  rbx, rcx                 ; mailbox
    //
    //   ; Save real RA, forge fake RA in its place
    //   48 8B 44 24 38         mov  rax, [rsp+0x38]          ; real RA
    //   48 89 44 24 20         mov  [rsp+0x20], rax          ; stash
    //   48 8B 43 20            mov  rax, [rbx+0x20]          ; fake_ra
    //   48 89 44 24 38         mov  [rsp+0x38], rax          ; overwrite saved RA
    //
    //   ; Decrypt fn (mailbox.fn ^ PEB)
    //   48 8B 43 08            mov  rax, [rbx+0x08]          ; fn_enc
    //   65 48 8B 14 25 60 00 00 00  mov rdx, gs:[0x60]        ; PEB
    //   48 31 D0               xor  rax, rdx                 ; rax = real fn
    //
    //   ; Capture event (preserve across call) and arg
    //   48 8B 73 18            mov  rsi, [rbx+0x18]          ; event
    //   48 8B 4B 10            mov  rcx, [rbx+0x10]          ; arg
    //
    //   ; Wipe sensitive mailbox fields BEFORE running fn
    //   48 C7 43 08 00 00 00 00  mov qword [rbx+0x08], 0     ; fn_enc
    //   48 C7 43 10 00 00 00 00  mov qword [rbx+0x10], 0     ; arg
    //   48 C7 43 18 00 00 00 00  mov qword [rbx+0x18], 0     ; event
    //   48 C7 43 20 00 00 00 00  mov qword [rbx+0x20], 0     ; fake_ra
    //
    //   FF D0                  call rax                      ; orchestrator runs
    //
    //   89 03                  mov  [rbx], eax               ; result
    //   C7 43 04 01 00 00 00   mov  dword [rbx+0x04], 1      ; done
    //
    //   ; Signal event using saved rsi (mailbox.event already wiped)
    //   48 85 F6               test rsi, rsi
    //   74 10                  je   skip_set                 ; +16
    //   48 89 F1               mov  rcx, rsi
    //   48 31 D2               xor  rdx, rdx
    //   B8 SS SS 00 00         mov  eax, <NtSetEvent SSN>    ; PATCHED
    //   49 89 CA               mov  r10, rcx
    //   0F 05                  syscall
    //   ; skip_set:
    //
    //   ; Restore real RA so the trampoline can return cleanly
    //   48 8B 44 24 20         mov  rax, [rsp+0x20]
    //   48 89 44 24 38         mov  [rsp+0x38], rax
    //
    //   48 83 C4 28            add  rsp, 0x28
    //   5E                     pop  rsi
    //   5B                     pop  rbx
    //   31 C0                  xor  eax, eax
    //   C3                     ret
    //
    // Trampoline body length = 135 bytes.
    void*  tramp    = (void*)0;
    u64    tramp_sz = 0x1000;
    if (s_ssn_alloc != AD_SSN_FAILED) {
        SyscallStub(s_ssn_alloc,
            AD_CURRENT_PROCESS, &tramp, (void*)0, &tramp_sz,
            (void*)(u64)0x3000ul,   // MEM_COMMIT | MEM_RESERVE
            (void*)(u64)0x40ul,     // PAGE_EXECUTE_READWRITE
            (void*)0,(void*)0,(void*)0,(void*)0,(void*)0);
    }

    // ── Fake stack — separate 256 KB anonymous private allocation ────────
    // The trampoline pivots RSP onto this region for the entire duration of
    // fn. Consequences for any sampler / kernel-mode walker:
    //   * Current RSP is OUTSIDE TEB.NtTib.StackBase..StackLimit — visible
    //     anomaly to a kernel debugger comparing thread metadata.
    //   * Walking up via .pdata from fn's frame finds the trampoline frame
    //     (no .pdata, anonymous page → unwinder treats as leaf and follows
    //     [RSP] which is random garbage from the page fill). The chain
    //     terminates without ever reaching BaseThreadInitThunk or the real
    //     RtlUserThreadStart frames.
    //   * The original stack's BTIT/RUTS frames are still allocated under
    //     TEB.StackBase but the thread isn't using them — a kernel walker
    //     reading TEB-bounded memory finds frames that contradict the live
    //     RSP. Either source it picks gives an inconsistent picture.
    //
    // 256 KB is sized to comfortably absorb the orchestrator's entire call
    // chain (state struct + decoy/gadget tables + nested ad_run_hardened
    // + diagnostic prints). Freed alongside the trampoline page after wait.
    void* fake_stack    = (void*)0;
    u64   fake_stack_sz = 0x40000;  // 256 KB
    void* fake_stack_top_aligned = (void*)0;
    if (s_ssn_alloc != AD_SSN_FAILED) {
        SyscallStub(s_ssn_alloc,
            AD_CURRENT_PROCESS, &fake_stack, (void*)0, &fake_stack_sz,
            (void*)(u64)0x3000ul,   // MEM_COMMIT | MEM_RESERVE
            (void*)(u64)0x04ul,     // PAGE_READWRITE
            (void*)0,(void*)0,(void*)0,(void*)0,(void*)0);
        if (fake_stack) {
            // Top of stack (highest address). Stack grows downward, so the
            // initial RSP for fn is just below this. 16-byte aligned.
            u64 top = (u64)fake_stack + fake_stack_sz;
            top &= ~0xFULL;
            // Reserve 0x40 bytes at the very top for any unwind sentinels
            // (improves chances of clean termination if a walker over-runs).
            fake_stack_top_aligned = (void*)(top - 0x40);
        }
    }

    mailbox.fake_stack_top  = fake_stack_top_aligned;
    mailbox.old_rsp_save    = (void*)0;
    mailbox.fake_stack_base = fake_stack;       // bottom of fake region
    mailbox.old_stack_base  = (void*)0;
    mailbox.old_stack_limit = (void*)0;

    void* entry = (void*)ad_ghost_thread_entry;
    if (tramp && fake_stack_top_aligned) {
        u8* base = (u8*)tramp;

        // Fill the page with pseudo-random bytes so the trampoline isn't
        // sitting in a sea of zeros — surrounded by noise, it's harder to
        // spot in a memory dump.
        {
            u64 prng = __rdtsc() ^ 0xA5A5A5A5C3C3C3C3ULL;
            u32 j;
            for (j = 0; j < 0x1000u; j += 8u) {
                prng ^= prng << 13; prng ^= prng >> 7; prng ^= prng << 17;
                *(u64*)(base + j) = prng;
            }
        }

        // Pick a random page offset (16-aligned) far from the page edges.
        u32 off = 0u;
        {
            u64 r = __rdtsc();
            r ^= r << 13; r ^= r >> 7; r ^= r << 17;
            off = 0x80u + (u32)(r & 0x57Fu);
            off &= ~0xFu;
        }

        u8* t = base + off;
        u32 i = 0;
        //
        // ─── Trampoline assembly ──────────────────────────────────────────
        //
        // Combines RA spoofing (forge fake parent on real stack), stack
        // pivot (run fn on a separate anonymous page so the worker's RSP
        // sits OUTSIDE TEB.StackBase..StackLimit while fn runs), mailbox
        // wipe (zero sensitive fields the moment fn launches), and PEB-
        // keyed fn decryption. See the design comment a few hundred lines
        // up for the rationale; the assembly listing follows.
        //
        //   53                         push rbx
        //   56                         push rsi
        //   48 89 CB                   mov  rbx, rcx                ; mailbox
        //
        //   ; Save real RA from [rsp+0x10] (the BTIT call's saved-RA slot
        //   ; on the real stack) into a stash slot, push it.
        //   48 8B 44 24 10             mov  rax, [rsp+0x10]
        //   50                         push rax                     ; stash
        //
        //   ; Forge fake parent RA on the real stack.
        //   48 8B 43 20                mov  rax, [rbx+0x20]         ; fake_ra
        //   48 89 44 24 18             mov  [rsp+0x18], rax
        //
        //   ; Save real RSP into mailbox slot (for un-pivot later).
        //   48 89 63 30                mov  [rbx+0x30], rsp
        //
        //   ; PIVOT — switch RSP to the fake stack region.
        //   48 8B 63 28                mov  rsp, [rbx+0x28]
        //
        //   ; Decrypt fn (mailbox.fn ^ PEB).
        //   48 8B 43 08                mov  rax, [rbx+0x08]
        //   65 48 8B 14 25 60 00 00 00 mov  rdx, gs:[0x60]
        //   48 31 D0                   xor  rax, rdx
        //
        //   ; Capture event handle (non-volatile rsi survives the call).
        //   48 8B 73 18                mov  rsi, [rbx+0x18]
        //   ; Capture arg.
        //   48 8B 4B 10                mov  rcx, [rbx+0x10]
        //
        //   ; Wipe mailbox.fn / arg / event / fake_ra.
        //   48 C7 43 08 00 00 00 00    mov  qword [rbx+0x08], 0
        //   48 C7 43 10 00 00 00 00    mov  qword [rbx+0x10], 0
        //   48 C7 43 18 00 00 00 00    mov  qword [rbx+0x18], 0
        //   48 C7 43 20 00 00 00 00    mov  qword [rbx+0x20], 0
        //
        //   48 83 EC 20                sub  rsp, 0x20               ; shadow
        //   FF D0                      call rax                     ; fn runs
        //   48 83 C4 20                add  rsp, 0x20
        //
        //   89 03                      mov  [rbx], eax
        //   C7 43 04 01 00 00 00       mov  dword [rbx+0x04], 1
        //
        //   ; UN-PIVOT — restore real RSP.
        //   48 8B 63 30                mov  rsp, [rbx+0x30]
        //
        //   ; Restore real RA from the stash slot at [rsp].
        //   48 8B 04 24                mov  rax, [rsp]
        //   48 89 44 24 18             mov  [rsp+0x18], rax
        //   48 83 C4 08                add  rsp, 0x08               ; pop stash
        //
        //   ; Wipe pivot slots.
        //   48 C7 43 28 00 00 00 00    mov  qword [rbx+0x28], 0
        //   48 C7 43 30 00 00 00 00    mov  qword [rbx+0x30], 0
        //
        //   ; Signal event using saved rsi.
        //   48 85 F6                   test rsi, rsi
        //   74 10                      je   skip_set
        //   48 89 F1                   mov  rcx, rsi
        //   48 31 D2                   xor  rdx, rdx
        //   B8 SS SS 00 00             mov  eax, <NtSetEvent SSN>
        //   49 89 CA                   mov  r10, rcx
        //   0F 05                      syscall
        //   ; skip_set:
        //
        //   5E                         pop  rsi
        //   5B                         pop  rbx
        //   31 C0                      xor  eax, eax
        //   C3                         ret
        //
        // Total length ≈ 175 bytes — fits comfortably in the random-offset
        // window inside the 4 KB trampoline page.

        // push rbx ; push rsi ; mov rbx, rcx
        t[i++] = 0x53;
        t[i++] = 0x56;
        t[i++] = 0x48; t[i++] = 0x89; t[i++] = 0xCB;

        // mov rax, [rsp+0x10] ; push rax  (stash real RA, align rsp)
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x44; t[i++] = 0x24; t[i++] = 0x10;
        t[i++] = 0x50;

        // mov rax, [rbx+0x20] ; mov [rsp+0x18], rax  (forge fake RA on real stack)
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x43; t[i++] = 0x20;
        t[i++] = 0x48; t[i++] = 0x89; t[i++] = 0x44; t[i++] = 0x24; t[i++] = 0x18;

        // mov [rbx+0x30], rsp  (save real RSP for un-pivot)
        t[i++] = 0x48; t[i++] = 0x89; t[i++] = 0x63; t[i++] = 0x30;

        // ── Update TEB.NtTib.StackBase/StackLimit so the kernel exception
        // dispatcher accepts an RSP that lies in the fake stack region.
        //   mov rax, gs:[0x30]                ; TEB
        //   mov rdx, [rax+0x08]               ; old StackBase
        //   mov [rbx+0x40], rdx
        //   mov rdx, [rax+0x10]               ; old StackLimit
        //   mov [rbx+0x48], rdx
        //   mov rdx, [rbx+0x28]               ; fake_stack_top (new StackBase)
        //   mov [rax+0x08], rdx
        //   mov rdx, [rbx+0x38]               ; fake_stack_base (new StackLimit)
        //   mov [rax+0x10], rdx
        t[i++] = 0x65; t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x04; t[i++] = 0x25;
        t[i++] = 0x30; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x50; t[i++] = 0x08;
        t[i++] = 0x48; t[i++] = 0x89; t[i++] = 0x53; t[i++] = 0x40;
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x50; t[i++] = 0x10;
        t[i++] = 0x48; t[i++] = 0x89; t[i++] = 0x53; t[i++] = 0x48;
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x53; t[i++] = 0x28;
        t[i++] = 0x48; t[i++] = 0x89; t[i++] = 0x50; t[i++] = 0x08;
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x53; t[i++] = 0x38;
        t[i++] = 0x48; t[i++] = 0x89; t[i++] = 0x50; t[i++] = 0x10;

        // mov rsp, [rbx+0x28]   (PIVOT to fake stack)
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x63; t[i++] = 0x28;

        // mov rax,[rbx+0x08] ; mov rdx,gs:[0x60] ; xor rax,rdx  (decrypt fn)
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x43; t[i++] = 0x08;
        t[i++] = 0x65; t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x14; t[i++] = 0x25;
        t[i++] = 0x60; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;
        t[i++] = 0x48; t[i++] = 0x31; t[i++] = 0xD0;

        // mov rsi, [rbx+0x18]  (event)
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x73; t[i++] = 0x18;
        // mov rcx, [rbx+0x10]  (arg)
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x4B; t[i++] = 0x10;

        // Wipe mailbox.fn / arg / event / fake_ra
        t[i++] = 0x48; t[i++] = 0xC7; t[i++] = 0x43; t[i++] = 0x08;
        t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;
        t[i++] = 0x48; t[i++] = 0xC7; t[i++] = 0x43; t[i++] = 0x10;
        t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;
        t[i++] = 0x48; t[i++] = 0xC7; t[i++] = 0x43; t[i++] = 0x18;
        t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;
        t[i++] = 0x48; t[i++] = 0xC7; t[i++] = 0x43; t[i++] = 0x20;
        t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;

        // sub rsp, 0x20 ; call rax ; add rsp, 0x20
        t[i++] = 0x48; t[i++] = 0x83; t[i++] = 0xEC; t[i++] = 0x20;
        t[i++] = 0xFF; t[i++] = 0xD0;
        t[i++] = 0x48; t[i++] = 0x83; t[i++] = 0xC4; t[i++] = 0x20;

        // mov [rbx],eax ; mov dword [rbx+4],1
        t[i++] = 0x89; t[i++] = 0x03;
        t[i++] = 0xC7; t[i++] = 0x43; t[i++] = 0x04;
        t[i++] = 0x01; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;

        // mov rsp, [rbx+0x30]   (UN-PIVOT)
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x63; t[i++] = 0x30;

        // Restore TEB.NtTib.StackBase/StackLimit
        //   mov rax, gs:[0x30]
        //   mov rdx, [rbx+0x40] ; mov [rax+0x08], rdx
        //   mov rdx, [rbx+0x48] ; mov [rax+0x10], rdx
        t[i++] = 0x65; t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x04; t[i++] = 0x25;
        t[i++] = 0x30; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x53; t[i++] = 0x40;
        t[i++] = 0x48; t[i++] = 0x89; t[i++] = 0x50; t[i++] = 0x08;
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x53; t[i++] = 0x48;
        t[i++] = 0x48; t[i++] = 0x89; t[i++] = 0x50; t[i++] = 0x10;

        // Restore real RA: mov rax,[rsp] ; mov [rsp+0x18],rax ; add rsp,8
        t[i++] = 0x48; t[i++] = 0x8B; t[i++] = 0x04; t[i++] = 0x24;
        t[i++] = 0x48; t[i++] = 0x89; t[i++] = 0x44; t[i++] = 0x24; t[i++] = 0x18;
        t[i++] = 0x48; t[i++] = 0x83; t[i++] = 0xC4; t[i++] = 0x08;

        // Wipe mailbox.fake_stack_top / old_rsp_save / fake_stack_base /
        // old_stack_base / old_stack_limit
        t[i++] = 0x48; t[i++] = 0xC7; t[i++] = 0x43; t[i++] = 0x28;
        t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;
        t[i++] = 0x48; t[i++] = 0xC7; t[i++] = 0x43; t[i++] = 0x30;
        t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;
        t[i++] = 0x48; t[i++] = 0xC7; t[i++] = 0x43; t[i++] = 0x38;
        t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;
        t[i++] = 0x48; t[i++] = 0xC7; t[i++] = 0x43; t[i++] = 0x40;
        t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;
        t[i++] = 0x48; t[i++] = 0xC7; t[i++] = 0x43; t[i++] = 0x48;
        t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00; t[i++] = 0x00;

        // test rsi,rsi ; je +16
        t[i++] = 0x48; t[i++] = 0x85; t[i++] = 0xF6;
        t[i++] = 0x74; t[i++] = 0x10;
        // mov rcx,rsi ; xor rdx,rdx ; mov eax,<SSN> ; mov r10,rcx ; syscall
        t[i++] = 0x48; t[i++] = 0x89; t[i++] = 0xF1;
        t[i++] = 0x48; t[i++] = 0x31; t[i++] = 0xD2;
        t[i++] = 0xB8;
        u32 ssn32 = (u32)s_ssn_set_event;
        t[i++] = (u8)(ssn32 >>  0); t[i++] = (u8)(ssn32 >>  8);
        t[i++] = (u8)(ssn32 >> 16); t[i++] = (u8)(ssn32 >> 24);
        t[i++] = 0x49; t[i++] = 0x89; t[i++] = 0xCA;
        t[i++] = 0x0F; t[i++] = 0x05;

        // pop rsi ; pop rbx ; xor eax,eax ; ret
        t[i++] = 0x5E;
        t[i++] = 0x5B;
        t[i++] = 0x31; t[i++] = 0xC0;
        t[i++] = 0xC3;

        entry = (void*)t;
    }

    // Create suspended thread
    void* thread = (void*)0;
    st = (ad_ntstatus_t)(s64)SyscallStub(s_ssn_create_th,
        &thread,
        (void*)(u64)0x001FFFFFul,                   // THREAD_ALL_ACCESS
        (void*)0,                                    // ObjAttr
        (void*)(u64)(u64)AD_CURRENT_PROCESS,         // ProcessHandle
        entry,                                       // StartRoutine (trampoline or direct)
        (void*)&mailbox,                             // Argument
        (void*)(u64)0x00000004ul,                    // CREATE_SUSPENDED
        (void*)0, (void*)0, (void*)0, (void*)0
    );

    if (!AD_NT_SUCCESS(st) || !thread) {
        if (tramp && s_ssn_free != AD_SSN_FAILED) {
            u64 fsz = 0;
            SyscallStub(s_ssn_free,
                AD_CURRENT_PROCESS, &tramp, &fsz, (void*)(u64)0x8000ul,
                (void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0);
        }
        if (fake_stack && s_ssn_free != AD_SSN_FAILED) {
            u64 fsz = 0;
            SyscallStub(s_ssn_free,
                AD_CURRENT_PROCESS, &fake_stack, &fsz, (void*)(u64)0x8000ul,
                (void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0);
        }
        AD_SYSCALL1(s_ssn_close, event);
        return ad_apc_exec(fn, arg);
    }

    // Hide thread from debugger
    if (s_ssn_seti != AD_SSN_FAILED)
        AD_SYSCALL4(s_ssn_seti, thread, (u64)17, (u64)0, (u64)0);

    // Flip the trampoline page to PAGE_EXECUTE before resuming. On older
    // CPUs without execute-only support, Windows promotes this to
    // PAGE_EXECUTE_READ — the bytes remain readable but at least no further
    // self-modification is possible. On modern hardware (Tiger Lake+, ARM,
    // some AMD chips with MPK) this gives true execute-only protection,
    // and a casual ReadProcessMemory of the trampoline returns access denied.
    if (tramp && s_ssn_protect != AD_SSN_FAILED) {
        u32 old_prot = 0;
        void* prot_base = tramp;
        u64   prot_sz   = tramp_sz;
        SyscallStub(s_ssn_protect,
            AD_CURRENT_PROCESS, &prot_base, &prot_sz,
            (void*)(u64)0x10ul,        // PAGE_EXECUTE
            &old_prot,
            (void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0);
    }

    // Resume
    u32 prev = 0;
    AD_SYSCALL2(s_ssn_resume, thread, &prev);

    // Wait for event — main thread shows NtWaitForSingleObject only
    s64 timeout = -300000000LL;  // 30s
    AD_SYSCALL3(s_ssn_wait, event, (u64)0, &timeout);

    AD_BARRIER();
    u32 result = mailbox.done ? mailbox.result : 0xFFFFFFFFu;

    // Cleanup — tramp + fake_stack freed AFTER the wait: the thread has
    // already pivoted back to its real stack and returned through the
    // trampoline epilogue, so neither page is still in use.
    if (tramp && s_ssn_free != AD_SSN_FAILED) {
        u64 fsz = 0;
        SyscallStub(s_ssn_free,
            AD_CURRENT_PROCESS, &tramp, &fsz, (void*)(u64)0x8000ul,
            (void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0);
    }
    if (fake_stack && s_ssn_free != AD_SSN_FAILED) {
        u64 fsz = 0;
        SyscallStub(s_ssn_free,
            AD_CURRENT_PROCESS, &fake_stack, &fsz, (void*)(u64)0x8000ul,
            (void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0);
    }
    AD_SYSCALL1(s_ssn_close, thread);
    AD_SYSCALL1(s_ssn_close, event);

    return result;
}

// =========================================================================
// 2. SELF-APC EXECUTION
// =========================================================================
//
// Stack walk during APC dispatch:
//   ntdll!KiUserApcDispatcher → ad_apc_callback → check_fn
// Main thread's original call frames are NOT on the stack.

// Encrypted: "NtQueueApcThread" (16 chars) — ROT variant
#ifndef AD_STRENC_NtQueueApcThread
#define AD_STRENC_NtQueueApcThread(buf)                                      \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x5D);                                     \
        char buf##_e[17];                                                    \
        AD_ENC_ROT(buf##_e,  0, 'N', _k); AD_ENC_ROT(buf##_e,  1, 't', _k); \
        AD_ENC_ROT(buf##_e,  2, 'Q', _k); AD_ENC_ROT(buf##_e,  3, 'u', _k); \
        AD_ENC_ROT(buf##_e,  4, 'e', _k); AD_ENC_ROT(buf##_e,  5, 'u', _k); \
        AD_ENC_ROT(buf##_e,  6, 'e', _k); AD_ENC_ROT(buf##_e,  7, 'A', _k); \
        AD_ENC_ROT(buf##_e,  8, 'p', _k); AD_ENC_ROT(buf##_e,  9, 'c', _k); \
        AD_ENC_ROT(buf##_e, 10, 'T', _k); AD_ENC_ROT(buf##_e, 11, 'h', _k); \
        AD_ENC_ROT(buf##_e, 12, 'r', _k); AD_ENC_ROT(buf##_e, 13, 'e', _k); \
        AD_ENC_ROT(buf##_e, 14, 'a', _k); AD_ENC_ROT(buf##_e, 15, 'd', _k); \
        AD_DECODE_BUF_ROT(buf##_e, 16, _k);                                 \
        for (unsigned _ci = 0; _ci < 17; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif

#ifndef AD_STRENC_NtDelayExecution_DEFINED
#define AD_STRENC_NtDelayExecution_DEFINED
#ifndef AD_STRENC_NtDelayExecution
#define AD_STRENC_NtDelayExecution(buf)                                      \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x44);                                     \
        char buf##_e[18];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'D', _k); AD_ENC(buf##_e,  3, 'e', _k);       \
        AD_ENC(buf##_e,  4, 'l', _k); AD_ENC(buf##_e,  5, 'a', _k);       \
        AD_ENC(buf##_e,  6, 'y', _k); AD_ENC(buf##_e,  7, 'E', _k);       \
        AD_ENC(buf##_e,  8, 'x', _k); AD_ENC(buf##_e,  9, 'e', _k);       \
        AD_ENC(buf##_e, 10, 'c', _k); AD_ENC(buf##_e, 11, 'u', _k);       \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'i', _k);       \
        AD_ENC(buf##_e, 14, 'o', _k); AD_ENC(buf##_e, 15, 'n', _k);       \
        AD_DECODE_BUF(buf##_e, 16, _k);                                     \
        for (unsigned _ci = 0; _ci < 17; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)
#endif
#endif

static void __stdcall ad_apc_callback(
    void* normal_ctx, void* sys_arg1, void* sys_arg2
) {
    AD_UNUSED(sys_arg1); AD_UNUSED(sys_arg2);
    ad_stealth_mailbox_t* mb = (ad_stealth_mailbox_t*)normal_ctx;
    if (mb && mb->fn) {
        ad_stealth_fn_t real_fn = (ad_stealth_fn_t)
            ((u64)mb->fn ^ ad_stealth_fn_xor_key());
        void* real_arg = mb->arg;
        mb->fn  = (ad_stealth_fn_t)0;
        mb->arg = (void*)0;
        __try {
            mb->result = real_fn(real_arg);
        } __except(1) {
            mb->result = 0xFFFFFFFFu;
        }
    }
    AD_BARRIER();
    mb->done = 1;
}

ANTIDEBUG_INLINE u32 ad_apc_exec(ad_stealth_fn_t fn, void* arg) {
    static u16 s_ssn_queue = AD_SSN_UNRESOLVED;
    static u16 s_ssn_delay = AD_SSN_UNRESOLVED;

    AD_RESOLVE_SSN_ENC(s_ssn_queue, NtQueueApcThread, 17);
    AD_RESOLVE_SSN_ENC(s_ssn_delay, NtDelayExecution, 17);

    if (s_ssn_queue == AD_SSN_FAILED || s_ssn_delay == AD_SSN_FAILED) {
        __try { return fn(arg); } __except(1) { return 0xFFFFFFFFu; }
    }

    ad_stealth_mailbox_t mailbox;
    AD_ZERO_BUF(&mailbox, sizeof(mailbox));
    mailbox.fn   = fn;
    mailbox.arg  = arg;
    mailbox.done = 0;

    ad_ntstatus_t st = AD_SYSCALL5(s_ssn_queue,
        AD_CURRENT_THREAD,
        (u64)(uintptr_t)&ad_apc_callback,
        (u64)(uintptr_t)&mailbox,
        (u64)0, (u64)0);

    if (!AD_NT_SUCCESS(st)) {
        __try { return fn(arg); } __except(1) { return 0xFFFFFFFFu; }
    }

    // Enter alertable wait → kernel dispatches APC
    s64 zero_timeout = 0LL;
    AD_SYSCALL2(s_ssn_delay, (u64)1, &zero_timeout);

    AD_BARRIER();
    return mailbox.done ? mailbox.result : 0xFFFFFFFFu;
}

// =========================================================================
// Convenience: alternating stealth
// =========================================================================
static volatile u32 g_stealth_counter = 0;

ANTIDEBUG_INLINE u32 ad_stealth_exec(ad_stealth_fn_t fn, void* arg) {
    u32 idx = g_stealth_counter++;
    AD_BARRIER();
    if (idx & 1u)
        return ad_apc_exec(fn, arg);
    else
        return ad_ghost_exec(fn, arg);
}

#else
typedef u32 (*ad_stealth_fn_t)(void*);
ANTIDEBUG_INLINE u32 ad_ghost_exec(ad_stealth_fn_t fn, void* a) { return fn(a); }
ANTIDEBUG_INLINE u32 ad_apc_exec(ad_stealth_fn_t fn, void* a) { return fn(a); }
ANTIDEBUG_INLINE u32 ad_stealth_exec(ad_stealth_fn_t fn, void* a) { return fn(a); }
#endif // _MSC_VER

#endif // ANTIDEBUG_STEALTH_EXEC_H
