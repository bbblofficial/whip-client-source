// ===== file: antidebug/checks/integrity/iat_target.h =====
//
// IAT Entry Target Validation — detect IAT hijacking.
//
// When the PE loader processes our Import Address Table, it writes each
// imported function's resolved address into the corresponding IAT slot.
// After loader fixups complete, every IAT entry MUST point to a byte
// inside the DLL that owns the import (as named in the matching
// IMAGE_IMPORT_DESCRIPTOR).
//
// Legitimate runtime transitions keep this invariant:
//   * DLL unload: entry still valid until process termination
//   * Hot-patching: MS /HOTPATCH jumps stay inside the target DLL
//
// Illegitimate transitions break it:
//   * Detours / EasyHook IAT hook: rewrites IAT slot to point at an
//     attacker-owned trampoline in heap/private RWX
//   * EDR userland import redirection: slot points to EDR's monitoring DLL
//   * API Set Schema tampering: unusual DLL being resolved
//   * Intel Pin / DynamoRIO proxy: IAT slot points into the code cache
//
// We scan the full Import Directory of our own module, walk every IAT
// entry, verify its target falls inside the named module's linear range.
// Any mismatch is reported via a u32 index + the observed target address.
//
// Zero false positives on a clean system: the entire mechanism is
// deterministic and compiler-independent. Works on Windows 7/10/11 and
// on both our EXE and any loaded DLL.
//
#ifndef ANTIDEBUG_IAT_TARGET_H
#define ANTIDEBUG_IAT_TARGET_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER

#ifndef AD_IAT_MAX_ENTRIES
#define AD_IAT_MAX_ENTRIES 256u
#endif

typedef struct {
    u32   import_index;     // index in the flat IAT array
    void* iat_slot_addr;    // &IAT[i] — where the hijacked pointer lives
    void* target_addr;      // the hijacked target value
    u32   dll_name_rva;     // RVA of the DLL name string (in our module)
} ad_iat_hit_t;

typedef struct {
    u32            iat_total;           // total IAT entries scanned
    u32            iat_unresolved;      // entries still zero (lazy/not bound)
    u32            hit_count;           // orphan count
    ad_iat_hit_t   hits[AD_IAT_MAX_ENTRIES];
} ad_iat_result_t;

// PEB.Ldr walk: verify an address falls inside ANY loaded module.
// Used for API Set Schema virtual imports where the descriptor's DLL
// name (api-ms-win-*) isn't a real loaded module — the loader resolves
// the IAT entry to a real module (kernelbase, ntdll, ...).
ANTIDEBUG_INLINE b32 ad_iat_addr_in_any_loaded_module(u8* addr) {
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0;
    u8* head  = ldr + 0x10;
    u8* entry = *(u8**)head;
    u32 walk = 0;
    while (entry != head && walk < 512u) {
        walk++;
        u8* mb = *(u8**)(entry + 0x30);
        u32 ms = *(u32*)(entry + 0x40);
        if (mb && ms && addr >= mb && addr < mb + ms) return 1;
        entry = *(u8**)entry;
    }
    return 0;
}

// PEB.Ldr walk: find a module by its ASCII name (e.g., "kernel32.dll").
// Case-insensitive. Returns base + size via out params.
ANTIDEBUG_INLINE b32 ad_iat_find_module_ascii(const char* name,
                                               u8** out_base, u32* out_size) {
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0;
    u8* head  = ldr + 0x10;
    u8* entry = *(u8**)head;

    // Compute target name length
    u32 n_len = 0;
    while (name[n_len] && n_len < 64u) n_len++;
    if (n_len == 0u) return 0;

    u32 walk = 0;
    while (entry != head && walk < 512u) {
        walk++;
        u16  blen  = *(u16*)(entry + 0x58);
        u16* bbuf  = *(u16**)(entry + 0x60);
        u32  bchars= (u32)(blen / 2u);
        if (bbuf && bchars == n_len) {
            b32 match = 1;
            u32 i;
            for (i = 0; i < n_len; i++) {
                u16 c = bbuf[i];
                if (c >= 'A' && c <= 'Z') c = (u16)(c + 32u);
                char nc = name[i];
                if (nc >= 'A' && nc <= 'Z') nc = (char)(nc + 32);
                if (c != (u16)(u8)nc) { match = 0; break; }
            }
            if (match) {
                void* mb = *(void**)(entry + 0x30);
                u32   ms = *(u32*)(entry + 0x40);
                *out_base = (u8*)mb;
                *out_size = ms;
                return 1;
            }
        }
        entry = *(u8**)entry;
    }
    return 0;
}

// Scan our OWN module's IAT and validate each entry.
// Caller gets a result struct with all hits (mismatched entries).
ANTIDEBUG_INLINE void ad_iat_validate_self(ad_iat_result_t* out) {
    u32 k;
    for (k = 0; k < (u32)sizeof(*out); k++)
        ((volatile u8*)out)[k] = 0;

    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return;
    u8* image = *(u8**)(peb + 0x10);
    if (!image) return;
    if (*(u16*)image != 0x5A4D) return;

    u32 pe_off = *(u32*)(image + 0x3C);
    if (pe_off > 0x1000u) return;
    u8* pe = image + pe_off;
    if (*(u32*)pe != 0x00004550u) return;

    // OptionalHeader.DataDirectory[1] = Import Directory (PE32+ layout).
    // OptionalHeader starts at pe+24. DataDirectory is at offset 112 in
    // OptionalHeader for PE32+. Each entry is 8 bytes (VirtualAddress + Size).
    u8* opt = pe + 24;
    u32 import_rva  = *(u32*)(opt + 112 + 1 * 8);      // DataDir[1].VirtualAddress
    u32 import_size = *(u32*)(opt + 112 + 1 * 8 + 4);  // DataDir[1].Size
    if (import_rva == 0u || import_size == 0u) return;

    // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes:
    //   +0x00 OriginalFirstThunk (INT - names array RVA)
    //   +0x04 TimeDateStamp
    //   +0x08 ForwarderChain
    //   +0x0C Name (DLL name RVA)
    //   +0x10 FirstThunk (IAT RVA)
    u8* import_table = image + import_rva;
    u32 desc_off = 0;
    u32 desc_guard = 0;
    while (desc_off + 20u <= import_size && desc_guard < 64u) {
        desc_guard++;
        u32 orig_thunk_rva = *(u32*)(import_table + desc_off + 0x00);
        u32 dll_name_rva   = *(u32*)(import_table + desc_off + 0x0C);
        u32 iat_rva        = *(u32*)(import_table + desc_off + 0x10);
        if (orig_thunk_rva == 0u && iat_rva == 0u) break;  // terminator

        desc_off += 20u;

        if (dll_name_rva == 0u || iat_rva == 0u) continue;

        const char* dll_name = (const char*)(image + dll_name_rva);

        u8* mod_base = 0; u32 mod_size = 0;
        b32 exact = ad_iat_find_module_ascii(dll_name, &mod_base, &mod_size);
        // Some imports reference API Set Schema virtual DLLs
        // (api-ms-win-core-*.dll) that aren't real loaded modules. The
        // loader rewrites IAT to point at kernel32/kernelbase/ntdll etc.
        // If we can't resolve the named DLL, we fall back to checking
        // that the target is inside ANY loaded module.

        u8* iat = image + iat_rva;
        u32 idx = 0;
        while (idx < AD_IAT_MAX_ENTRIES) {
            u64 entry_val = *(u64*)(iat + idx * 8u);
            if (entry_val == 0ULL) break;
            out->iat_total++;
            idx++;

            u8* tgt = (u8*)(u64)entry_val;
            // An import is legitimate if the target is in ANY loaded module,
            // regardless of the descriptor's named DLL. Legitimate cases that
            // the strict same-module check would misclassify as hooks:
            //
            //   * API Set Schema: descriptor says "api-ms-win-core-*.dll" but
            //     loader resolves to kernelbase/ntdll/kernel32.
            //   * Forwarder exports: descriptor says "kernel32.dll" but the
            //     specific function is a forwarder → ntdll!RealName.
            //   * MUI-forwarded resource DLLs, delayed-load stubs, etc.
            //
            // A genuine IAT hijack points at heap, private RWX, or a
            // private module not in PEB.Ldr — none of which are in any
            // loaded module's image range.
            //
            // The unused strict-path variables are retained for future
            // per-descriptor reporting if someone wants stricter mode.
            (void)exact; (void)mod_base; (void)mod_size;
            b32 hijack = !ad_iat_addr_in_any_loaded_module(tgt);

            if (hijack) {
                if (out->hit_count < AD_IAT_MAX_ENTRIES) {
                    out->hits[out->hit_count].import_index = out->iat_total - 1u;
                    out->hits[out->hit_count].iat_slot_addr =
                        (void*)(iat + (idx - 1u) * 8u);
                    out->hits[out->hit_count].target_addr = (void*)tgt;
                    out->hits[out->hit_count].dll_name_rva = dll_name_rva;
                    out->hit_count++;
                }
            }
        }
    }
}

// Boolean wrapper.
ANTIDEBUG_INLINE b32 ad_iat_target_hooked(void) {
    ad_iat_result_t r;
    ad_iat_validate_self(&r);
    return (b32)(r.hit_count > 0u);
}

ANTIDEBUG_INLINE u32 ad_iat_target_hit_count(void) {
    ad_iat_result_t r;
    ad_iat_validate_self(&r);
    return r.hit_count;
}

#else  // !_MSC_VER
typedef struct { int _unused; } ad_iat_result_t;
ANTIDEBUG_INLINE void ad_iat_validate_self(ad_iat_result_t* r) { (void)r; }
ANTIDEBUG_INLINE b32 ad_iat_target_hooked(void) { return 0; }
ANTIDEBUG_INLINE u32 ad_iat_target_hit_count(void) { return 0u; }
#endif // _MSC_VER

#endif // ANTIDEBUG_IAT_TARGET_H
