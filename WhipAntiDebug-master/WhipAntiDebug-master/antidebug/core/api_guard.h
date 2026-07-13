// ===== file: antidebug/core/api_guard.h =====
//
// Cross-validation guard for ad_resolve_api().
//
// Attack vector: hooking ad_resolve_api or tampering with PEB module lists
// lets an attacker redirect all API resolution. Since ad_resolve_api is
// ANTIDEBUG_INLINE (no single address to hook), the real risk is PEB list
// manipulation or export table patching.
//
// Defence: resolve the same (module_hash, func_hash) pair via TWO different
// PEB linked lists. The primary resolver (api_hash.h) walks
// InMemoryOrderModuleList; this module walks InLoadOrderModuleList. If the
// two results diverge, the PEB or a module's export table is tampered.
//
#ifndef ANTIDEBUG_API_GUARD_H
#define ANTIDEBUG_API_GUARD_H

#include "types.h"
#include "macros.h"
#include "api_hash.h"

// ---------------------------------------------------------------------------
// Alternate module finder via PEB.Ldr.InLoadOrderModuleList
//
// InLoadOrderModuleList head is at Ldr + 0x10.
// Each LIST_ENTRY is at the VERY START of LDR_DATA_TABLE_ENTRY (offset 0x00),
// so entry == cur (no subtraction needed, unlike InMemoryOrder).
//
// LDR_DATA_TABLE_ENTRY offsets (x64):
//   +0x00  InLoadOrderLinks        (LIST_ENTRY)
//   +0x10  InMemoryOrderLinks      (LIST_ENTRY)
//   +0x20  InInitializationOrderLinks (LIST_ENTRY)
//   +0x30  DllBase                 (void*)
//   ...
//   +0x58  BaseDllName             (UNICODE_STRING: u16 Len, u16 MaxLen, pad, u16* Buf)
//   +0x60  BaseDllName.Buffer      (u16*)
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u8* ad_find_module_by_hash_alt(u32 module_hash) {
#ifdef _MSC_VER
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0;

    // InLoadOrderModuleList head at ldr + 0x10
    u8* head = ldr + 0x10;
    u8* cur  = *(u8**)head;
    u32 walks = 0;

    while (cur && cur != head && walks < 256u) {
        // cur IS the start of LDR_DATA_TABLE_ENTRY (InLoadOrderLinks is at +0x00)
        u8* entry = cur;
        void* dll_base = *(void**)(entry + 0x30);

        // BaseDllName UNICODE_STRING at offset +0x58
        u16  name_len_bytes = *(u16*)(entry + 0x58);
        u16* name_buf       = *(u16**)(entry + 0x60);

        if (dll_base && name_buf && name_len_bytes >= 2u) {
            u32 name_chars = (u32)(name_len_bytes / 2u);
            if (ad_hash_wstr(name_buf, name_chars) == module_hash) {
                return (u8*)dll_base;
            }
        }

        cur = *(u8**)cur;   // Flink
        walks++;
    }
    return 0;
#else
    AD_UNUSED(module_hash);
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// Alternate full resolver — uses InLoadOrderModuleList, same PE export walk
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void* ad_resolve_api_alt(u32 module_hash, u32 func_hash) {
    u8* base = ad_find_module_by_hash_alt(module_hash);
    if (!base) return 0;
    return ad_pe_resolve_export(base, func_hash);
}

// ---------------------------------------------------------------------------
// Cross-validate: resolve via both PEB lists, compare results.
// Returns 1 if tampered (mismatch), 0 if consistent.
//
// NOTE: we bypass the LRU cache by calling the raw helpers directly so that
// a poisoned cache cannot mask divergence.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_api_cross_validate(u32 module_hash, u32 func_hash) {
    // Primary path: InMemoryOrderModuleList (same as api_hash.h)
    u8* base1 = ad_find_module_by_hash(module_hash);
    void* result1 = base1 ? ad_pe_resolve_export(base1, func_hash) : 0;

    // Alternate path: InLoadOrderModuleList
    void* result2 = ad_resolve_api_alt(module_hash, func_hash);

    // Both NULL is fine (function legitimately not found).
    // Mismatch when one found and the other didn't, or addresses differ.
    if (result1 != result2) return 1;

    // Extra: if we got a result, verify it falls inside the module's image
    if (result1 && base1) {
        u32 pe_off = *(u32*)(base1 + 0x3C);
        u8* pe = base1 + pe_off;
        u32 image_size = *(u32*)(pe + 24 + 56);  // SizeOfImage in OptionalHeader
        u64 fn_addr = (u64)(u8*)result1;
        u64 mod_start = (u64)base1;
        if (fn_addr < mod_start || fn_addr >= mod_start + image_size) {
            return 1;  // resolved address outside module bounds
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Prologue hook check — verify a resolved function isn't hooked before calling.
//
// Inline hooks overwrite the first bytes of a function with:
//   E9 xx xx xx xx          — JMP rel32
//   FF 25 xx xx xx xx       — JMP [rip+disp32]
//   48 B8 xx...xx FF E0     — MOV RAX,imm64; JMP RAX
//   CC                      — INT3 (breakpoint)
//
// Returns 1 if the function prologue looks hooked.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_api_is_hooked(const void* fn) {
    if (!fn) return 0;
    const u8* p = (const u8*)fn;

    u8 b0 = p[0];
    u8 b1 = p[1];

    // JMP rel32
    if (b0 == 0xE9u) return 1;
    // JMP [rip+disp32]
    if (b0 == 0xFFu && b1 == 0x25u) return 1;
    // INT3 at function start
    if (b0 == 0xCCu) return 1;
    // MOV RAX,imm64 (48 B8) + JMP RAX (FF E0) or CALL RAX (FF D0)
    if (b0 == 0x48u && b1 == 0xB8u) {
        if (p[10] == 0xFFu && (p[11] == 0xE0u || p[11] == 0xD0u)) return 1;
    }
    // NOP sled (2+ NOPs = hook padding)
    if (b0 == 0x90u && b1 == 0x90u) return 1;

    return 0;
}

// Resolve + validate: resolve an API and verify its prologue isn't hooked.
// Returns the function pointer if clean, NULL if hooked or not found.
ANTIDEBUG_INLINE void* ad_resolve_api_safe(u32 module_hash, u32 func_hash) {
    void* fn = ad_resolve_api(module_hash, func_hash);
    if (!fn) return 0;
    if (ad_api_is_hooked(fn)) return 0;
    return fn;
}

#endif // ANTIDEBUG_API_GUARD_H
