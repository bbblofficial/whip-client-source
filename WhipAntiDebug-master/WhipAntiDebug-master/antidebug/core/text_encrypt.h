// ===== file: antidebug/core/text_encrypt.h =====
//
// Runtime .text section encryption / decryption ("text armor").
//
// Purpose
// -------
// Encrypt the DLL's .text section when not actively running checks,
// so that a dumper reading memory between check windows gets XOR'd
// ciphertext instead of executable code. Decrypt on demand, execute
// the check pass, then re-encrypt.
//
// The lock/unlock functions themselves are placed in a separate PE
// section (.armor) via #pragma code_seg so they are NOT covered by
// their own encryption.
//
// Usage
// -----
//   ad_text_armor_t armor = {0};
//   ad_text_armor_init(&armor, my_dll_base);
//   // ...
//   ad_text_armor_lock(&armor);     // .text is now ciphertext
//   // ... time passes, dumpers see garbage ...
//   ad_text_armor_unlock(&armor);   // .text is readable/executable again
//   run_checks();
//   ad_text_armor_lock(&armor);     // re-encrypt
//
#ifndef ANTIDEBUG_TEXT_ENCRYPT_H
#define ANTIDEBUG_TEXT_ENCRYPT_H

#include "types.h"
#include "macros.h"
#include "api_hash.h"

// ---------------------------------------------------------------------------
// Context structure
// ---------------------------------------------------------------------------
typedef struct {
    void*  text_base;      // VA of .text section
    u32    text_size;      // size of .text in bytes
    u64    xor_key;        // runtime XOR key (RDTSC + module base)
    b32    encrypted;      // current state: 0 = plaintext, 1 = encrypted
    void*  pNtProtect;     // cached NtProtectVirtualMemory (resolved at init)
} ad_text_armor_t;

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// NtProtectVirtualMemory typedef
//   NTSTATUS NtProtectVirtualMemory(
//       HANDLE  ProcessHandle,     // -1 = current process
//       PVOID*  BaseAddress,
//       PSIZE_T RegionSize,
//       ULONG   NewProtect,
//       PULONG  OldProtect);
// ---------------------------------------------------------------------------
typedef ad_ntstatus_t (__stdcall *fn_NtProtectVirtualMemory)(
    ad_handle_t ProcessHandle,
    void**      BaseAddress,
    u64*        RegionSize,
    u32         NewProtect,
    u32*        OldProtect
);

// Page protection constants (no windows.h)
#ifndef AD_PAGE_EXECUTE_READ
#define AD_PAGE_EXECUTE_READ         0x20UL
#endif
#ifndef AD_PAGE_EXECUTE_READWRITE
#define AD_PAGE_EXECUTE_READWRITE    0x40UL
#endif

// ---------------------------------------------------------------------------
// Init: locate .text section from PE headers, derive XOR key.
// Does NOT encrypt yet.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_text_armor_init(ad_text_armor_t* ctx, void* module_base) {
    ctx->text_base = 0;
    ctx->text_size = 0;
    ctx->xor_key   = 0;
    ctx->encrypted = 0;

    if (!module_base) return;

    u8* base = (u8*)module_base;

    // Validate MZ
    if (*(u16*)base != 0x5A4D) return;

    u32 pe_off = *(u32*)(base + 0x3C);
    u8* pe = base + pe_off;

    // Validate PE signature
    if (*(u32*)pe != 0x00004550u) return;

    // COFF header starts at pe + 4
    u16 num_sections    = *(u16*)(pe + 6);
    u16 opt_header_size = *(u16*)(pe + 20);

    // Section headers start after optional header
    u8* section_hdr = pe + 24 + opt_header_size;

    // Walk sections looking for ".text"
    u32 i;
    for (i = 0; i < num_sections; i++) {
        u8* sec = section_hdr + (i * 40u);  // IMAGE_SECTION_HEADER is 40 bytes

        // Section name is first 8 bytes
        // Check for ".text\0" (0x2E 0x74 0x65 0x78 0x74 0x00)
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' &&
            sec[3] == 'x' && sec[4] == 't' && sec[5] == '\0') {

            u32 virt_size = *(u32*)(sec + 8);   // Misc.VirtualSize
            u32 virt_addr = *(u32*)(sec + 12);  // VirtualAddress (RVA)

            if (virt_size == 0 || virt_addr == 0) return;

            ctx->text_base = (void*)(base + virt_addr);
            ctx->text_size = virt_size;
            break;
        }
    }

    if (!ctx->text_base) return;

    // Derive XOR key: RDTSC mixed with module base address for uniqueness
    u64 tsc = __rdtsc();
    u64 mod = (u64)module_base;
    // Mix bits: rotate TSC by some of the module base low bits, then XOR
    ctx->xor_key = tsc ^ (mod * 0x9E3779B97F4A7C15ULL);

    // Ensure key is non-zero (a zero key is a no-op)
    if (ctx->xor_key == 0) ctx->xor_key = 0xDEADBEEFCAFEBABEULL;

    // Pre-resolve NtProtectVirtualMemory NOW while .text is still readable
    // The lock/unlock functions live in .armor and must NOT call back into .text
    ctx->pNtProtect = ad_resolve_api(AD_HASH_NTDLL, AD_HASH("NtProtectVirtualMemory"));

    AD_BARRIER();
}

// ---------------------------------------------------------------------------
// Internal: XOR the .text section in 8-byte qwords.
// Handles a trailing partial qword if text_size is not 8-aligned.
//
// Placed in .armor section so it is NOT encrypted by itself.
// ---------------------------------------------------------------------------
#pragma code_seg(".armor")

static NOINLINE void ad_text_armor_xor_section(ad_text_armor_t* ctx) {
    if (!ctx->text_base || !ctx->text_size || !ctx->xor_key) return;

    // Use pre-resolved NtProtectVirtualMemory (cached at init time)
    // We MUST NOT call back into .text here — it may be encrypted
    fn_NtProtectVirtualMemory pNtProtect = (fn_NtProtectVirtualMemory)ctx->pNtProtect;
    if (!pNtProtect) return;

    void* region_base = ctx->text_base;
    u64   region_size = (u64)ctx->text_size;
    u32   old_protect = 0;

    // Change to RWX so we can modify code bytes
    ad_ntstatus_t st = pNtProtect(
        AD_CURRENT_PROCESS,
        &region_base,
        &region_size,
        AD_PAGE_EXECUTE_READWRITE,
        &old_protect);
    if (!AD_NT_SUCCESS(st)) return;

    AD_BARRIER();

    // XOR in 8-byte qwords
    u64* qwords  = (u64*)ctx->text_base;
    u32  qcount  = ctx->text_size / 8u;
    u64  key     = ctx->xor_key;
    u32  i;

    for (i = 0; i < qcount; i++) {
        qwords[i] ^= key;
    }

    // Handle trailing bytes (if text_size is not 8-aligned)
    u32 remainder = ctx->text_size & 7u;
    if (remainder) {
        u8* tail = (u8*)ctx->text_base + (qcount * 8u);
        u8* kbytes = (u8*)&key;
        u32 j;
        for (j = 0; j < remainder; j++) {
            tail[j] ^= kbytes[j];
        }
    }

    AD_BARRIER();

    // Restore to RX (execute + read, no write)
    region_base = ctx->text_base;
    region_size = (u64)ctx->text_size;
    pNtProtect(
        AD_CURRENT_PROCESS,
        &region_base,
        &region_size,
        AD_PAGE_EXECUTE_READ,
        &old_protect);

    AD_BARRIER();
}

// ---------------------------------------------------------------------------
// Lock: encrypt .text section (plaintext -> ciphertext)
// ---------------------------------------------------------------------------
static NOINLINE void ad_text_armor_lock(ad_text_armor_t* ctx) {
    if (!ctx || ctx->encrypted) return;
    ad_text_armor_xor_section(ctx);
    ctx->encrypted = 1;
    AD_BARRIER();
}

// ---------------------------------------------------------------------------
// Unlock: decrypt .text section (ciphertext -> plaintext)
// XOR is symmetric, so we call the same XOR function.
// ---------------------------------------------------------------------------
static NOINLINE void ad_text_armor_unlock(ad_text_armor_t* ctx) {
    if (!ctx || !ctx->encrypted) return;
    ad_text_armor_xor_section(ctx);
    ctx->encrypted = 0;
    AD_BARRIER();
}

#pragma code_seg()

#else
// Non-MSVC stubs
ANTIDEBUG_INLINE void ad_text_armor_init(ad_text_armor_t* ctx, void* module_base) {
    AD_UNUSED(ctx); AD_UNUSED(module_base);
}
static NOINLINE void ad_text_armor_lock(ad_text_armor_t* ctx)   { AD_UNUSED(ctx); }
static NOINLINE void ad_text_armor_unlock(ad_text_armor_t* ctx) { AD_UNUSED(ctx); }
#endif // _MSC_VER

#endif // ANTIDEBUG_TEXT_ENCRYPT_H
