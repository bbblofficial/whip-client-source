// ===== file: antidebug/stack/main_ra_spoof.h =====
//
// Saved-RA Spoof for the entry-point frame.
//
// PURPOSE
// -------
// On x64 Windows, an unwinder walking up from `main` lands at the saved
// return-address slot stored in main's caller frame. Normally that RA
// points inside `kernel32!BaseThreadInitThunk` — the textbook "main was
// called from BaseThreadInitThunk" stack trace.
//
// We overwrite that slot at main's prologue so the saved RA points
// somewhere INSIDE `ntdll!RtlUserThreadStart` (a function that exists
// in every Win32 process and has valid unwind info). When a stack
// walker — x64dbg, WinDbg `k`, RtlCaptureStackBackTrace — unwinds main's
// caller, it follows the fake address into ntdll, applies that
// function's unwind codes, and continues climbing. The visible trace
// becomes:
//
//     ...→ ntdll!RtlUserThreadStart+<offset> → main → NtWaitForSingleObject
//
// instead of the real:
//
//     ...→ kernel32!BaseThreadInitThunk → main → NtWaitForSingleObject
//
// The parent of main is now FAKE. Combined with running main's payload
// inside a detached `ad_ghost_exec` worker thread (whose stack does not
// contain main at all), this satisfies "main n'apparait pas + truc faux
// apparait" for both threads:
//
//   - Worker thread:  no main visible (work runs in a separate thread)
//   - Main thread:    main visible but parent + body are forged
//
// SAFETY
// ------
// We do NOT restore the original RA. main exits via `ad_terminate_self`
// (direct NtTerminateProcess) — control flow never unwinds back through
// the corrupted slot, so the program does not crash on return.
//
#ifndef ANTIDEBUG_MAIN_RA_SPOOF_H
#define ANTIDEBUG_MAIN_RA_SPOOF_H

#include "../core/types.h"
#include "../core/macros.h"
#include "../core/api_hash.h"
#include "../core/syscall_bridge.h"
#include "../core/string_encrypt.h"
#include "../core/strenc_extra.h"

// AD_STRENC_NtProtectVirtualMemory is defined (under #ifndef guards) in several
// places in the framework (anti_breakin.h, anti_dump.h, guard_pages.h,
// self_protect.h, latent_tamper2.h). When main_ra_spoof.h is the first header
// pulled in by an external integrator (via stack_cpp.hpp), none of those have
// been seen yet → ad_hide_main_pdata fails to compile. Provide a self-contained
// fallback definition here, gated by the same #ifndef.
#ifndef AD_STRENC_NtProtectVirtualMemory
#define AD_STRENC_NtProtectVirtualMemory(buf)                                \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x3B);                                      \
        char buf##_e[23];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);          \
        AD_ENC(buf##_e,  2, 'P', _k); AD_ENC(buf##_e,  3, 'r', _k);          \
        AD_ENC(buf##_e,  4, 'o', _k); AD_ENC(buf##_e,  5, 't', _k);          \
        AD_ENC(buf##_e,  6, 'e', _k); AD_ENC(buf##_e,  7, 'c', _k);          \
        AD_ENC(buf##_e,  8, 't', _k); AD_ENC(buf##_e,  9, 'V', _k);          \
        AD_ENC(buf##_e, 10, 'i', _k); AD_ENC(buf##_e, 11, 'r', _k);          \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'u', _k);          \
        AD_ENC(buf##_e, 14, 'a', _k); AD_ENC(buf##_e, 15, 'l', _k);          \
        AD_ENC(buf##_e, 16, 'M', _k); AD_ENC(buf##_e, 17, 'e', _k);          \
        AD_ENC(buf##_e, 18, 'm', _k); AD_ENC(buf##_e, 19, 'o', _k);          \
        AD_ENC(buf##_e, 20, 'r', _k); AD_ENC(buf##_e, 21, 'y', _k);          \
        AD_DECODE_BUF(buf##_e, 22, _k);                                      \
        for (unsigned _ci = 0; _ci < 23; _ci++) (buf)[_ci] = buf##_e[_ci];   \
    } while(0)
#endif

#ifdef _MSC_VER

// MSVC intrinsic — returns a pointer to the slot on the parent frame
// that holds the return-address main was called via.
void* _AddressOfReturnAddress(void);
#pragma intrinsic(_AddressOfReturnAddress)

// Detect a HotSpot JVM in the process by looking for jvm.dll in PEB.Ldr.
// HotSpot walks every thread's stack on safepoints (GC, JIT compile,
// deopt) by reading saved-RA slots. A forged RA pointing into the body
// of RtlUserThreadStart (mid-instruction, no matching unwind frame) is
// not a legitimate return site → the walker dereferences garbage when
// it tries to resolve the next frame → access violation → process dies.
//
// LoadLibrary'd DLLs see this too, but in their normal execution path
// the client thread sits inside an OpenGL/render loop with the original
// RA still on the stack at the BOTTOM of a deep call chain — the JVM
// walker often stops higher up before touching the corrupted slot. With
// manual mapping plus our short-init thread, the corrupted slot is at
// frame 1 and the walker hits it almost immediately.
//
// Cheaper than a full bytecode test: just check whether jvm.dll is in
// the loader list. If yes, opt out of RA spoofing — the stealth value
// is not worth crashing the host process.
ANTIDEBUG_INLINE int ad_running_inside_jvm(void) {
    int found = 0;
    __try {
        u8* peb = (u8*)__readgsqword(0x60);
        if (!peb) return 0;
        u8* ldr = *(u8**)(peb + 0x18);
        if (!ldr) return 0;
        // PEB_LDR_DATA.InLoadOrderModuleList = +0x10 (sentinel LIST_ENTRY).
        u8* list_head = ldr + 0x10;
        u8* entry = *(u8**)list_head;
        int safety = 0;
        while (entry && entry != list_head && safety++ < 512) {
            // LDR_DATA_TABLE_ENTRY layout (x64): BaseDllName UNICODE_STRING at +0x58.
            //   USHORT Length;          // +0x58
            //   USHORT MaximumLength;   // +0x5A
            //   ULONG  _pad;            // +0x5C
            //   PWSTR  Buffer;          // +0x60
            unsigned short len = *(unsigned short*)(entry + 0x58);
            const wchar_t* buf = *(const wchar_t* const*)(entry + 0x60);
            if (buf && len >= 14u /* "jvm.dll" */) {
                unsigned wlen = (unsigned)(len / 2u);
                // Tail-match "jvm.dll" case-insensitive.
                const wchar_t* tail = buf + wlen - 7u;
                wchar_t a, b;
#define _AD_TOLOW(c) ((c) >= L'A' && (c) <= L'Z' ? (wchar_t)((c) + 32) : (c))
                int matched =
                    ((a=_AD_TOLOW(tail[0])) == L'j') &&
                    ((a=_AD_TOLOW(tail[1])) == L'v') &&
                    ((a=_AD_TOLOW(tail[2])) == L'm') &&
                    ((b=tail[3]) == L'.') &&
                    ((a=_AD_TOLOW(tail[4])) == L'd') &&
                    ((a=_AD_TOLOW(tail[5])) == L'l') &&
                    ((a=_AD_TOLOW(tail[6])) == L'l');
#undef _AD_TOLOW
                if (matched) { found = 1; break; }
            }
            // Next InLoadOrderLinks.Flink (offset 0 of LDR_DATA_TABLE_ENTRY).
            entry = *(u8**)entry;
        }
    } __except(1) {
        // PEB read fault. Conservatively claim "JVM present" — that just
        // disables RA spoof, never an unsafe choice.
        found = 1;
    }
    return found;
}

// Pick a target inside ntdll!RtlUserThreadStart for the fake parent.
// RtlUserThreadStart is exported and has well-formed unwind info, so an
// unwinder following the spoofed RA into it will continue cleanly to
// the bottom of the stack instead of bombing out on bad metadata.
ANTIDEBUG_INLINE void* ad_main_ra_pick_target(void) {
    void* p = ad_resolve_api(AD_HASH_NTDLL, ad_hash_str("RtlUserThreadStart"));
    if (!p) return (void*)0;
    // Offset 0x21 lands inside the body, past the prologue. The exact
    // offset is irrelevant for unwinder correctness — any address
    // covered by the function's RUNTIME_FUNCTION entry works.
    return (void*)((u8*)p + 0x21);
}

// Overwrite main's saved RA. Call from the very first lines of main()
// so the spoofed value is in place before any heavy work begins (and
// before any sampler can capture the original RA from the slot).
//
// No-op when running inside a HotSpot JVM (jvm.dll loaded). HotSpot
// walks every thread's stack on safepoints; a forged RA mid-function
// in RtlUserThreadStart breaks the walker and crashes the host process.
ANTIDEBUG_INLINE void ad_main_ra_spoof(void) {
    if (ad_running_inside_jvm()) return;
    void* fake = ad_main_ra_pick_target();
    if (!fake) return;
    void** ra_slot = (void**)_AddressOfReturnAddress();
    // _AddressOfReturnAddress points AT the saved-RA slot of the calling
    // function (i.e., inside main's prologue this points at the slot the
    // CRT pushed when it CALL'd main). Overwriting it forges main's parent.
    *ra_slot = fake;
}

// ─────────────────────────────────────────────────────────────────────
// .pdata removal — strip main's RUNTIME_FUNCTION entry.
//
// Saved-RA spoofing forges main's PARENT frame on the stack, but main
// itself is still labelled "main" by any stack walker that resolves the
// RIP through the .pdata exception directory: every x64 Windows function
// has a RUNTIME_FUNCTION { BeginAddress, EndAddress, UnwindData } entry,
// and unwinders binary-search this table to find which function a given
// RIP belongs to. main's entry is what makes WinDbg/x64dbg/etc. label the
// frame "main" (or the nearest export+offset when no PDB is loaded).
//
// At runtime we walk the PE headers, locate main's RUNTIME_FUNCTION, and
// zero its BeginAddress + EndAddress. The result:
//   * Binary-searching for main's RIP returns no matching entry.
//   * Stack walkers fall through to "no function info" — the frame is
//     labelled with a hex offset or the nearest-export decoy
//     (ai_symbols.c provides plenty of misleading export names).
//   * The unwinder treats main as a leaf function: saved RA assumed at
//     [RSP+0] — which we already forged via ad_main_ra_spoof(), so the
//     fake parent chain remains consistent.
//
// The .pdata section is read-only by default; we VirtualProtect to RW
// before patching, restore RO afterwards.
//
// Safety: main is small and its body never raises an unhandled exception
// that needs to unwind through the now-stripped pdata entry. main exits
// via direct NtTerminateProcess so the unwinder is never asked to walk
// main's frame for a real cleanup either.
//
ANTIDEBUG_INLINE void ad_hide_main_pdata(void* main_addr) {
    // Image base via PEB (gs:[0x60] → +0x10 ImageBaseAddress)
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return;
    u8* base = *(u8**)(peb + 0x10);
    if (!base) return;

    // PE headers
    u32 e_lfanew = *(u32*)(base + 0x3C);
    u8* nt = base + e_lfanew;                   // IMAGE_NT_HEADERS64
    // OptionalHeader at nt + 0x18, DataDirectory at +0x70 of OptionalHeader
    u8* dd = nt + 0x18 + 0x70;
    // IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
    u32 exc_rva  = *(u32*)(dd + 3 * 8 + 0);
    u32 exc_size = *(u32*)(dd + 3 * 8 + 4);
    if (!exc_rva || exc_size < 12u) return;

    u8* pdata = base + exc_rva;
    u32 count = exc_size / 12u;                  // sizeof(RUNTIME_FUNCTION)

    u32 main_rva = (u32)((u64)main_addr - (u64)base);

    // Linear scan — small N (a few thousand), trivial cost. Avoids needing
    // to validate sort order (which a malicious linker might disturb).
    u32 hit = 0xFFFFFFFFu;
    for (u32 i = 0; i < count; i++) {
        u32 b = *(u32*)(pdata + i * 12 + 0);
        u32 e = *(u32*)(pdata + i * 12 + 4);
        if (main_rva >= b && main_rva < e) { hit = i; break; }
    }
    if (hit == 0xFFFFFFFFu) return;

    // Pick a 1-byte range that PRESERVES sort order AND avoids covering
    // main's executing code. The project's own .pdata anti-tamper check
    // flags BOTH unsorted entries AND entries with EndAddress <= BeginAddress
    // (zero-width is treated as suspicious). We need:
    //   - Begin >= prev_entry.End  (sort order)
    //   - End   <= next_entry.Begin (sort order)
    //   - End   >  Begin            (passes e<=b sanity check)
    //   - The range does NOT overlap main's actual code
    //
    // Strategy: put a 1-byte sentinel at the BOUNDARY between main's old
    // range and the next entry. Since main_end == next_begin in MSVC's
    // packed .pdata, [next_begin-1, next_begin) sits at main's last byte
    // — usually `c3` (RET) padding, never actually executed because main
    // exits via NtTerminateProcess. The unwinder asking for any other RIP
    // in main's old range finds NO match (range was strictly main_begin..
    // main_end-1, now collapsed to a 1-byte slice).
    u32 main_begin = *(u32*)(pdata + hit * 12 + 0);
    u32 main_end   = *(u32*)(pdata + hit * 12 + 4);
    u32 sentinel_b = (main_end > main_begin) ? (main_end - 1u) : main_begin;
    u32 sentinel_e = main_end;

    // VirtualProtect the .pdata page(s) to RW via direct syscall.
    static u16 s_ssn_protect = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_protect, NtProtectVirtualMemory, 23);
    if (s_ssn_protect == AD_SSN_FAILED) return;

    void* prot_base = pdata + hit * 12;
    u64   prot_sz   = 12;
    u32   old_prot  = 0;
    SyscallStub(s_ssn_protect,
        AD_CURRENT_PROCESS, &prot_base, &prot_sz,
        (void*)(u64)0x04ul,                       // PAGE_READWRITE
        &old_prot,
        (void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0);

    // Collapse to a 1-byte range at the very end of main's original range.
    // Binary-search for any RIP in main's body (i.e., main_begin .. main_end-1)
    // now finds NO entry; only the final byte (a RET / padding) maps. The
    // table stays monotonic and the anti-tamper sanity check (e > b) passes.
    *(volatile u32*)(pdata + hit * 12 + 0) = sentinel_b;
    *(volatile u32*)(pdata + hit * 12 + 4) = sentinel_e;

    // Restore original protection (typically PAGE_READONLY).
    if (old_prot != 0u) {
        u32 throwaway = 0;
        SyscallStub(s_ssn_protect,
            AD_CURRENT_PROCESS, &prot_base, &prot_sz,
            (void*)(u64)old_prot, &throwaway,
            (void*)0,(void*)0,(void*)0,(void*)0,(void*)0,(void*)0);
    }
}

#else  // !_MSC_VER

ANTIDEBUG_INLINE void ad_main_ra_spoof(void) { /* no-op */ }
ANTIDEBUG_INLINE void ad_hide_main_pdata(void* a) { (void)a; }

#endif // _MSC_VER

#endif // ANTIDEBUG_MAIN_RA_SPOOF_H
