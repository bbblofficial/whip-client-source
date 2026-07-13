// ===== file: antidebug/checks/runtime/anti_dump.h =====
//
// Anti-dump: erase PE headers from memory at runtime.
//
// Technique:
//   Tools like PEDump, Scylla, x64dbg's dump plugin read the PE headers
//   (DOS header, PE signature, section table) from memory to reconstruct
//   the executable. By zeroing these headers, the dumped file is corrupt
//   and cannot be loaded/analyzed.
//
//   We use NtProtectVirtualMemory via syscall to change the page protection
//   to RW, zero the header, then set it to PAGE_NOACCESS — any future read
//   of the header region triggers an access violation.
//
#ifndef ANTIDEBUG_ANTI_DUMP_H
#define ANTIDEBUG_ANTI_DUMP_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "../debug/peb.h"

// NT memory protection constants
#ifndef AD_PAGE_READWRITE
#define AD_PAGE_READWRITE   0x04UL
#endif
#ifndef AD_PAGE_NOACCESS
#define AD_PAGE_NOACCESS    0x01UL
#endif

// ---------------------------------------------------------------------------
// Encrypted string: "NtProtectVirtualMemory" (22 chars)
// ---------------------------------------------------------------------------
#define AD_STRENC_NtProtectVirtualMemory(buf)                                \
    do {                                                                     \
        const u8 _k = AD_STR_KEY(0x3B);                                     \
        char buf##_e[23];                                                    \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);       \
        AD_ENC(buf##_e,  2, 'P', _k); AD_ENC(buf##_e,  3, 'r', _k);       \
        AD_ENC(buf##_e,  4, 'o', _k); AD_ENC(buf##_e,  5, 't', _k);       \
        AD_ENC(buf##_e,  6, 'e', _k); AD_ENC(buf##_e,  7, 'c', _k);       \
        AD_ENC(buf##_e,  8, 't', _k); AD_ENC(buf##_e,  9, 'V', _k);       \
        AD_ENC(buf##_e, 10, 'i', _k); AD_ENC(buf##_e, 11, 'r', _k);       \
        AD_ENC(buf##_e, 12, 't', _k); AD_ENC(buf##_e, 13, 'u', _k);       \
        AD_ENC(buf##_e, 14, 'a', _k); AD_ENC(buf##_e, 15, 'l', _k);       \
        AD_ENC(buf##_e, 16, 'M', _k); AD_ENC(buf##_e, 17, 'e', _k);       \
        AD_ENC(buf##_e, 18, 'm', _k); AD_ENC(buf##_e, 19, 'o', _k);       \
        AD_ENC(buf##_e, 20, 'r', _k); AD_ENC(buf##_e, 21, 'y', _k);       \
        AD_DECODE_BUF(buf##_e, 22, _k);                                     \
        for (unsigned _ci = 0; _ci < 23; _ci++) (buf)[_ci] = buf##_e[_ci];  \
    } while (0)

// ---------------------------------------------------------------------------
// Erase PE headers of the current module from memory.
//
// After this call:
//   - PE dump tools produce a corrupt file
//   - Reading the image base page triggers ACCESS_VIOLATION
//   - Module is still running (code pages are unaffected)
//
// Call once at init, after all header-dependent operations are done
// (image base detection, section scanning, etc.).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_erase_pe_header(void* image_base) {
    if (!image_base) return 0;

    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtProtectVirtualMemory, 23);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u8*  base_addr  = (u8*)image_base;
    u64  region_size = 0x1000ULL;  // first page (4KB) = PE headers
    u32  old_protect = 0;

    // Step 1: change to PAGE_READWRITE so we can zero it
    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        &base_addr,
        &region_size,
        (u64)AD_PAGE_READWRITE,
        &old_protect
    );
    if (!AD_NT_SUCCESS(st)) return 0;

    // Step 2: zero out the entire first page (DOS + PE + section headers)
    AD_ZERO_BUF(base_addr, (u32)region_size);

    // Step 3: set to PAGE_NOACCESS — any read triggers AV
    u32 old2 = 0;
    base_addr   = (u8*)image_base;
    region_size = 0x1000ULL;
    AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        &base_addr,
        &region_size,
        (u64)AD_PAGE_NOACCESS,
        &old2
    );

    return 1;
}

// ---------------------------------------------------------------------------
// Inflate SizeOfImage in the PE optional header.
//
// Technique (from al-khaser SizeOfImage.cpp):
//   PE dump tools (Scylla, x64dbg dump, PEDump) read SizeOfImage to know
//   how many bytes to extract from memory. Setting it to an absurdly large
//   value causes:
//     - Dump tools to attempt allocating/writing gigabytes of data → failure
//     - Reconstructed PE to have a corrupt size field → unloadable
//
//   We set it to 0x77777777 (≈2GB). This is large enough to break any
//   tool doing a naïve full-image dump but small enough to avoid an
//   immediate integer overflow in 64-bit dump logic.
//
// Call once, after all PE header-dependent operations (code hash, etc.)
// are complete, alongside ad_erase_pe_header().
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_size_of_image_inflate(void* image_base) {
    if (!image_base) return 0;

    u8* base = (u8*)image_base;
    if (*(u16*)base != 0x5A4Du) return 0;   // MZ check

    u32 pe_off = *(u32*)(base + 0x3Cu);
    u8* pe = base + pe_off;
    if (*(u32*)pe != 0x00004550u) return 0; // PE signature

    // OptionalHeader begins at pe + 0x18
    u8* opt = pe + 0x18u;
    // SizeOfImage is at opt + 0x38 for BOTH PE32 and PE32+
    // (same offset because ImageBase shift is compensated by stack sizes)
    u32* size_ptr = (u32*)(opt + 0x38u);

    // Make the header page writable
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtProtectVirtualMemory, 23);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u8*  page_base  = (u8*)((u64)size_ptr & ~(u64)0xFFFu);
    u64  reg_size   = 0x1000ULL;
    u32  old_prot   = 0u;

    ad_ntstatus_t st = AD_SYSCALL5(
        s_ssn,
        AD_CURRENT_PROCESS,
        &page_base,
        &reg_size,
        (u64)AD_PAGE_READWRITE,
        &old_prot
    );
    if (!AD_NT_SUCCESS(st)) return 0;

    // Corrupt SizeOfImage — large enough to defeat dump tools
    *size_ptr = 0x77777777UL;

    // Restore original page protection
    u32 tmp     = 0u;
    page_base   = (u8*)((u64)size_ptr & ~(u64)0xFFFu);
    reg_size    = 0x1000ULL;
    AD_SYSCALL5(s_ssn, AD_CURRENT_PROCESS, &page_base, &reg_size,
                (u64)old_prot, &tmp);

    return 1;
}

// ---------------------------------------------------------------------------
// Erase the PE header of ntdll.dll too — prevents tools from parsing
// ntdll exports to find syscall stubs after our init is done.
// AGGRESSIVE: may break legitimate code that parses ntdll exports at runtime.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_erase_ntdll_header(void) {
    void* ntdll = ad_ntdll_base();
    if (!ntdll) return 0;
    return ad_erase_pe_header(ntdll);
}

#endif // ANTIDEBUG_ANTI_DUMP_H
