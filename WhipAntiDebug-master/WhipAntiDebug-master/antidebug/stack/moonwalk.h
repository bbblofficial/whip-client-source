// ===== file: antidebug/stack/moonwalk.h =====
//
// Stack call-chain spoofing — "moonwalk".
//
// Principle:
//   When a debugger (x64dbg, WinDbg) inspects the call stack, it follows
//   the return addresses stored on the stack. By overwriting those addresses
//   with values that point into legitimate system modules (ntdll, kernel32),
//   the debugger sees a clean, system-originated call chain instead of our
//   real one.
//
//   Example — real stack:
//     our_check()  ← called from
//     ad_run()     ← called from
//     main_loop()  ← called from
//     WinMain()
//
//   After moonwalk — what the debugger sees:
//     our_check()  ← called from
//     ntdll!RtlpAllocateHeap+0x4A   (decoy)
//     ntdll!RtlAllocateHeap+0x12    (decoy)
//     kernel32!BaseThreadInitThunk  (decoy)
//
// Architecture (x64, MSVC):
//
//   Single-frame (C only):
//     ad_moonwalk_begin() / ad_moonwalk_end()
//     Spoofs the immediate caller's return address.
//     Safe: saves and restores before returning.
//
//   Multi-frame (ASM trampoline in moonwalk_stub.asm):
//     MoonwalkCall(fn, n_frames, decoy_table, args...)
//     Walks N frames and overwrites all of them before calling fn.
//
// Usage pattern:
//
//   void my_sensitive_function(void) {
//       ad_moonwalk_ctx_t ctx;
//       ad_moonwalk_begin(&ctx, ad_pick_decoy(0));  // spoof caller frame
//
//       // ... sensitive work ...
//       // Debugger inspecting stack here sees ntdll as our caller
//
//       ad_moonwalk_end(&ctx);                       // restore real ret addr
//   }
//
#ifndef ANTIDEBUG_MOONWALK_H
#define ANTIDEBUG_MOONWALK_H

#include "../core/types.h"
#include "../core/macros.h"

#if defined(_MSC_VER)
#include <intrin.h>
#endif

// ---------------------------------------------------------------------------
// Decoy address discovery
//
// We need real code addresses inside system modules to use as fake return
// addresses. The decoy must point to valid executable code — ideally somewhere
// that looks like it could plausibly be a return site (after a CALL instruction).
//
// Strategy:
//   1. Get ntdll base from PEB LDR (second InLoadOrderModuleList entry)
//   2. Scan ntdll's PE header to find the .text section bounds
//   3. Scan for a RET (0xC3) byte that is preceded by non-0xCC bytes
//   4. Return the address of that RET — it looks like a valid function epilogue
// ---------------------------------------------------------------------------

// Get ntdll.dll base address via PEB.Ldr walk (no imports, no IAT).
// InLoadOrderModuleList:
//   Entry 0 → our EXE (or mapped DLL)
//   Entry 1 → ntdll.dll  (always second on Windows)
ANTIDEBUG_INLINE void* ad_ntdll_base(void) {
#if defined(_MSC_VER)
    u8* peb    = (u8*)__readgsqword(0x60);
    u8* ldr    = *(u8**)(peb  + 0x18);   // PEB.Ldr
    u8* first  = *(u8**)(ldr  + 0x10);   // InLoadOrderModuleList.Flink → entry 0
    u8* second = *(u8**)first;            // entry 0 → entry 1 (ntdll)
    return *(void**)(second + 0x30);      // LDR_DATA_TABLE_ENTRY.DllBase
#else
    return (void*)0;
#endif
}

// Walk PE headers to find .text section bounds.
// Returns 0 on failure, section length on success. Sets *out_start.
ANTIDEBUG_INLINE u32 ad_find_text_section(void* mod_base, u8** out_start) {
    if (!mod_base) return 0;
    u8* base = (u8*)mod_base;

    // DOS header → e_lfanew
    u32 pe_off = *(u32*)(base + 0x3C);
    u8* pe     = base + pe_off;

    // Signature check: 'PE\0\0'
    if (*(u32*)pe != 0x00004550u) return 0;

    // Optional header offset
    u16 opt_hdr_size = *(u16*)(pe + 0x14);
    u16 num_sections = *(u16*)(pe + 0x06);
    u8* sections     = pe + 0x18 + opt_hdr_size;  // first IMAGE_SECTION_HEADER

    u32 i;
    for (i = 0; i < (u32)num_sections; i++) {
        u8* sec = sections + i * 40;  // sizeof(IMAGE_SECTION_HEADER) = 40

        // Section name is 8 bytes at offset 0
        // Check for ".text" (0x74786574 = 'text', 0x2E = '.')
        u32 name0 = *(u32*)(sec + 0);
        u32 name4 = *(u32*)(sec + 4);

        // ".text\0\0\0" → little-endian: 0x7478652E, 0x00000074
        if (name0 == 0x7478652Eu && (name4 & 0xFF) == 0x74u) {
            u32 vsize  = *(u32*)(sec + 0x10);  // Misc.VirtualSize
            u32 vrva   = *(u32*)(sec + 0x0C);  // VirtualAddress
            *out_start = base + vrva;
            return vsize;
        }
    }
    return 0;
}

// Scan [region, region+len) for a plausible RET-based decoy address.
// We look for: non-0xCC byte, non-0xCC byte, 0xC3 (RET).
// The returned pointer is the RET byte — a good fake "return to" site.
ANTIDEBUG_INLINE void* ad_scan_for_ret(const u8* region, u32 len) {
    if (!region || len < 3u) return (void*)0;
    u32 i;
    for (i = 2u; i < len; i++) {
        if (region[i]   == (u8)0xC3 &&   // RET
            region[i-1] != (u8)0xCC &&   // not INT3
            region[i-2] != (u8)0xCC) {
            return (void*)&region[i];
        }
    }
    return (void*)0;
}

// ---------------------------------------------------------------------------
// Decoy table
//
// Pre-discover up to AD_DECOY_TABLE_SIZE decoy addresses from ntdll.
// Call ad_decoy_table_init() once at startup (inside ad_init).
// Use ad_pick_decoy(n) to get the n-th entry.
// ---------------------------------------------------------------------------
#define AD_DECOY_TABLE_SIZE 8u

typedef struct {
    void* addrs[AD_DECOY_TABLE_SIZE];
    u32   count;
    b32   ready;
} ad_decoy_table_t;

// Discover decoy addresses by scanning ntdll .text section.
// Results are stored in tbl. Call once at init.
ANTIDEBUG_INLINE void ad_decoy_table_init(ad_decoy_table_t* tbl) {
    AD_ZERO_BUF(tbl, sizeof(*tbl));

    void* ntdll = ad_ntdll_base();
    if (!ntdll) return;

    u8* text_start = (u8*)0;
    u32 text_len   = ad_find_text_section(ntdll, &text_start);
    if (!text_len || !text_start) return;

    // Collect AD_DECOY_TABLE_SIZE distinct RET addresses, spread across .text
    u32 stride = text_len / (AD_DECOY_TABLE_SIZE + 1u);
    u32 i;
    for (i = 0; i < AD_DECOY_TABLE_SIZE; i++) {
        u32   off  = stride * (i + 1u);
        void* addr = ad_scan_for_ret(text_start + off,
                                     stride < 0x400u ? stride : 0x400u);
        if (!addr) {
            // fallback: fixed offset into ntdll .text
            addr = (void*)(text_start + off + 8u);
        }
        tbl->addrs[i] = addr;
    }
    tbl->count = AD_DECOY_TABLE_SIZE;
    tbl->ready = 1;
}

// Return the n-th decoy address (wraps around if n >= count).
ANTIDEBUG_INLINE void* ad_pick_decoy(const ad_decoy_table_t* tbl, u32 n) {
    if (!tbl->ready || tbl->count == 0u) return (void*)0;
    return tbl->addrs[n % tbl->count];
}

// ---------------------------------------------------------------------------
// Single-frame moonwalk (pure C, MSVC x64)
//
// Spoofs the return address of the function that CALLS ad_moonwalk_begin.
// Because ad_moonwalk_begin is __forceinline, _AddressOfReturnAddress()
// resolves to the return-address slot of the CALLING frame on the stack.
//
// Stack layout when caller invokes a function:
//
//   [RSP+0x00]  → return address of caller  ← _AddressOfReturnAddress()
//   [RSP+0x08]  → shadow space / args
//   ...
//
// We overwrite [RSP+0x00] with decoy. The debugger sees decoy as where
// "the current function will return to", making it look like the call
// chain goes: current_fn ← ntdll_decoy ← ...
// ---------------------------------------------------------------------------
typedef struct {
    void*  real_ret;   // original return address we saved
    void** slot;       // pointer to the stack slot we modified
} ad_moonwalk_ctx_t;

// Begin spoofing: call at entry of the function you want to appear clean.
// decoy: address to write into the return-address slot (from ad_pick_decoy).
ANTIDEBUG_INLINE void ad_moonwalk_begin(ad_moonwalk_ctx_t* ctx, void* decoy) {
#if defined(_MSC_VER)
    ctx->slot     = (void**)_AddressOfReturnAddress();
    ctx->real_ret = *ctx->slot;
    if (decoy) {
        *ctx->slot = decoy;
    }
#else
    ctx->slot     = (void**)0;
    ctx->real_ret = (void*)0;
    AD_UNUSED(decoy);
#endif
}

// End spoofing: MUST be called before returning from the function.
// Restores the real return address so execution continues correctly.
ANTIDEBUG_INLINE void ad_moonwalk_end(ad_moonwalk_ctx_t* ctx) {
    if (ctx->slot) {
        *ctx->slot = ctx->real_ret;
    }
}

// ---------------------------------------------------------------------------
// Multi-frame stack burn ("full moonwalk")
//
// Walks up to `depth` stack frames and overwrites each frame's return address
// with the corresponding entry from `decoys[]`.
//
// On x64 with frame pointers (compiled with /Oy-), each frame looks like:
//
//   [RBP+0x00] → saved RBP of caller (frame pointer chain)
//   [RBP+0x08] → return address of this frame
//
// Without frame pointers (/O2 default), the chain is broken and this walk
// requires parsing unwind info. For now: only reliable with /Oy-.
// Use __declspec(noinline) + #pragma optimize("y", off) at call site.
//
// saved_rets[] and ret_slots[] MUST have at least `depth` entries.
// Call ad_stack_restore() with the same arrays to undo.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_stack_burn(
    u32    depth,
    void** decoys,       // array of [depth] decoy addresses
    void** saved_rets,   // caller-allocated save buffer [depth]
    void*** ret_slots    // caller-allocated slot pointer buffer [depth]
) {
#if defined(_MSC_VER)
    // Start from the frame pointer of OUR caller (two levels up because
    // ad_stack_burn itself is __forceinline, so it shares the caller's frame).
    // We read the current RBP via the MSVC-specific intrinsic.
    //
    // NOTE: This requires frame pointers. Add to the calling function:
    //   #pragma optimize("y", off)   // disable frame pointer omission
    //   __declspec(noinline) static void my_fn(void) { ... }
    //

    // Get current frame pointer (RBP on x64)
    u8* fp = (u8*)_AddressOfReturnAddress() - sizeof(void*);
    // fp now points to: [saved_RBP | ret_addr_of_caller]
    // i.e. fp+0 = saved RBP, fp+8 = return address

    u32 i;
    for (i = 0u; i < depth; i++) {
        void** ret_slot = (void**)(fp + sizeof(void*));

        // Save original and write decoy
        saved_rets[i] = *ret_slot;
        ret_slots[i]  = ret_slot;
        if (decoys && decoys[i]) {
            *ret_slot = decoys[i];
        }

        // Walk to next frame: fp = *fp (follow saved RBP chain)
        u8* parent_fp = *(u8**)fp;
        if (!parent_fp || parent_fp <= fp) break;  // guard: no infinite walk
        fp = parent_fp;
    }
    return i;
#else
    AD_UNUSED(depth); AD_UNUSED(decoys);
    AD_UNUSED(saved_rets); AD_UNUSED(ret_slots);
    return 0u;
#endif
}

// Restore a stack previously burned by ad_stack_burn().
ANTIDEBUG_INLINE void ad_stack_restore(
    u32    depth,
    void** saved_rets,
    void*** ret_slots
) {
    u32 i;
    for (i = 0u; i < depth; i++) {
        if (ret_slots[i]) {
            *ret_slots[i] = saved_rets[i];
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience: single-call full-burn wrapper
//
// Burns the call stack to `depth` frames using entries from the decoy table,
// then calls fn(), then restores. The function fn sees a spoofed stack the
// whole time it runs.
//
// fn MUST be __declspec(noinline) to prevent inlining across frame boundaries.
// ---------------------------------------------------------------------------
#define AD_MAX_BURN_DEPTH 8u

ANTIDEBUG_INLINE void ad_moonwalk_call(
    void (*fn)(void* arg),
    void* arg,
    u32   depth,
    const ad_decoy_table_t* tbl
) {
    void*  decoys[AD_MAX_BURN_DEPTH];
    void*  saved[AD_MAX_BURN_DEPTH];
    void** slots[AD_MAX_BURN_DEPTH];

    if (depth > AD_MAX_BURN_DEPTH) depth = AD_MAX_BURN_DEPTH;

    u32 i;
    for (i = 0u; i < depth; i++) {
        decoys[i] = ad_pick_decoy(tbl, i);
    }

    u32 n = ad_stack_burn(depth, decoys, saved, slots);
    fn(arg);
    ad_stack_restore(n, saved, slots);
}

#endif // ANTIDEBUG_MOONWALK_H
