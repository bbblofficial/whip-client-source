// ===== file: antidebug/checks/runtime/write_watch.h =====
//
// WriteWatch-based sandbox/DBI instrumentation detection — al-khaser inspired.
//
// Technique:
//   VirtualAlloc with MEM_WRITE_WATCH tracks every write to an allocation.
//   Normal code should produce exactly the number of writes WE perform.
//   Any additional writes come from:
//     - Sandbox agents monitoring memory
//     - DBI frameworks (PIN, DynamoRIO) that may write trampoline code
//     - Debuggers that hook/instrument APIs touching our region
//
//   Strategy:
//     1. Allocate page with MEM_WRITE_WATCH | MEM_RESERVE | MEM_COMMIT
//     2. Write ONE byte to it — expect GetWriteWatch count == 1
//     3. Reset counters. Perform NO further writes. Wait briefly.
//     4. Query again — any non-zero count = external entity wrote to our page
//
//   GetWriteWatch is kernel32.dll only (no Nt equivalent). We resolve it
//   by walking PEB→Ldr to find kernel32, then walking its PE export table.
//   Zero IAT footprint — the function pointer is obtained at runtime.
//
#ifndef ANTIDEBUG_WRITE_WATCH_H
#define ANTIDEBUG_WRITE_WATCH_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

// Memory allocation flags
#define AD_MEM_WRITE_WATCH  0x00200000UL

// Reuse from guard_pages.h if already included, otherwise define locally
#ifndef AD_MEM_COMMIT
#define AD_MEM_COMMIT       0x00001000UL
#endif
#ifndef AD_MEM_RESERVE
#define AD_MEM_RESERVE      0x00002000UL
#endif
#ifndef AD_MEM_RELEASE
#define AD_MEM_RELEASE      0x00008000UL
#endif
#ifndef AD_PAGE_RW
#define AD_PAGE_RW          0x04UL
#endif

// GetWriteWatch flag: reset counters after query
#define AD_WRITE_WATCH_FLAG_RESET 0x00000001UL

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// PE export table walker
//
// Finds a named export in an in-memory PE module.
// No CRT, no imports, works for both PE32 and PE32+.
// Returns the function RVA resolved to an absolute pointer, or NULL.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void* ad_pe_find_export(const u8* mod, const char* name) {
    if (!mod || !name) return (void*)0;

    // Verify MZ
    if (*(const u16*)mod != 0x5A4Du) return (void*)0;

    // PE header offset
    u32 pe_off = *(const u32*)(mod + 0x3Cu);
    const u8* pe = mod + pe_off;
    if (*(const u32*)pe != 0x00004550u) return (void*)0;

    // Optional header — determine PE32 vs PE32+ for DataDirectory offset
    const u8* opt  = pe + 0x18u;
    u16 magic      = *(const u16*)opt;
    u32 exp_rva;
    if (magic == (u16)0x20Bu) {
        exp_rva = *(const u32*)(opt + 0x70u);   // PE32+ DataDirectory[0].VirtualAddress
    } else if (magic == (u16)0x10Bu) {
        exp_rva = *(const u32*)(opt + 0x60u);   // PE32  DataDirectory[0].VirtualAddress
    } else {
        return (void*)0;
    }
    if (exp_rva == 0u) return (void*)0;

    // Export directory
    const u8* exp  = mod + exp_rva;
    u32 n_names    = *(const u32*)(exp + 0x18u);   // NumberOfNames
    u32 n_funcs    = *(const u32*)(exp + 0x14u);   // NumberOfFunctions
    u32 names_rva  = *(const u32*)(exp + 0x20u);   // AddressOfNames
    u32 ords_rva   = *(const u32*)(exp + 0x24u);   // AddressOfNameOrdinals
    u32 funcs_rva  = *(const u32*)(exp + 0x1Cu);   // AddressOfFunctions

    if (!n_names || !n_funcs) return (void*)0;

    const u32* names = (const u32*)(mod + names_rva);
    const u16* ords  = (const u16*)(mod + ords_rva);
    const u32* funcs = (const u32*)(mod + funcs_rva);

    u32 i;
    for (i = 0u; i < n_names; i++) {
        const char* ename = (const char*)(mod + names[i]);
        // Compare byte-by-byte
        const char* a = name;
        const char* b = ename;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0) {
            u16 ord = ords[i];
            if ((u32)ord < n_funcs) {
                u32 fn_rva = funcs[ord];
                if (fn_rva) return (void*)(mod + fn_rva);
            }
        }
    }
    return (void*)0;
}

// ---------------------------------------------------------------------------
// PEB Ldr module finder
//
// Walks InLoadOrderModuleList and returns the DllBase for the first entry
// whose BaseDllName (case-insensitive) ends with `target_name[0..len-1]`.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void* ad_find_module_ci(const u16* target, u32 tlen) {
    u8* peb       = (u8*)__readgsqword(0x60u);
    u8* ldr       = *(u8**)(peb + 0x18u);
    u8* list_head = ldr + 0x10u;            // InLoadOrderModuleList head
    u8* entry     = *(u8**)list_head;       // first Flink

    u32 guard = 0u;
    while (entry && entry != list_head && guard < 256u) {
        guard++;
        // LDR_DATA_TABLE_ENTRY x64:
        //   +0x30 DllBase
        //   +0x58 BaseDllName.Length (u16, bytes)
        //   +0x60 BaseDllName.Buffer (wchar_t*)
        void* dll_base   = *(void**)(entry + 0x30u);
        u16   name_bytes = *(u16*) (entry + 0x58u);
        u16*  name_buf   = *(u16**)(entry + 0x60u);

        if (dll_base && name_buf && name_bytes > 0u) {
            u32 nchars = (u32)(name_bytes / 2u);
            if (nchars >= tlen) {
                const u16* p = name_buf + (nchars - tlen);
                b32 match = 1;
                u32 j;
                for (j = 0u; j < tlen && match; j++) {
                    u16 a = p[j];
                    u16 b_ch = target[j];
                    if (a  >= (u16)'a' && a  <= (u16)'z') a  = (u16)(a  - 0x20u);
                    if (b_ch >= (u16)'a' && b_ch <= (u16)'z') b_ch = (u16)(b_ch - 0x20u);
                    if (a != b_ch) match = 0;
                }
                if (match) return dll_base;
            }
        }
        entry = *(u8**)entry;   // Flink
    }
    return (void*)0;
}

// GetWriteWatch function pointer typedef (kernel32.dll export)
// UINT WINAPI GetWriteWatch(DWORD, PVOID, SIZE_T, PVOID*, ULONG_PTR*, LPDWORD)
typedef u32 (__stdcall *AD_PFN_GetWriteWatch)(
    u32    dwFlags,
    void*  lpBaseAddress,
    u64    dwRegionSize,
    void** lpAddresses,
    u64*   lpdwCount,
    u32*   lpdwGranularity
);

// ---------------------------------------------------------------------------
// Check: WriteWatch — detect unexpected memory writes
//
// If the write count after a single controlled write is not 1, or if extra
// writes appear when we perform none, an external agent is touching memory.
//
// Returns 1 if anomaly detected (sandbox or DBI instrumentation).
// Returns 0 if clean, or if GetWriteWatch is unavailable.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_write_watch_check(void) {
    static u16 s_ssn_alloc = AD_SSN_UNRESOLVED;
    static u16 s_ssn_free  = AD_SSN_UNRESOLVED;

    AD_RESOLVE_SSN_ENC(s_ssn_alloc, NtAllocateVirtualMemory, 24);
    AD_RESOLVE_SSN_ENC(s_ssn_free,  NtFreeVirtualMemory,     20);

    if (s_ssn_alloc == AD_SSN_FAILED || s_ssn_free == AD_SSN_FAILED) return 0;

    // Find kernel32.dll — it is always loaded; we need it for GetWriteWatch
    static const u16 k32[] = {'K','E','R','N','E','L','3','2','.','D','L','L'};  // 12 chars
    void* k32_base = ad_find_module_ci(k32, 12u);
    if (!k32_base) return 0;

    AD_PFN_GetWriteWatch fn_gww = (AD_PFN_GetWriteWatch)
        ad_pe_find_export((const u8*)k32_base, "GetWriteWatch");
    if (!fn_gww) return 0;

    // Allocate one monitored page (MEM_WRITE_WATCH must be combined with MEM_RESERVE)
    void* buf        = (void*)0;
    u64   reg_size   = 0x1000ULL;

    ad_ntstatus_t st = AD_SYSCALL6(
        s_ssn_alloc,
        AD_CURRENT_PROCESS,
        &buf,
        (u64)0,
        &reg_size,
        (u64)(AD_MEM_RESERVE | AD_MEM_COMMIT | AD_MEM_WRITE_WATCH),
        (u64)AD_PAGE_RW
    );
    if (!AD_NT_SUCCESS(st) || !buf) return 0;

    b32 suspicious = 0;

    // ── Test 1: write once, expect count == 1 ──────────────────────────────
    volatile u8* vbuf = (volatile u8*)buf;
    vbuf[0] = (u8)0xAD;
    AD_BARRIER();

    void*  addrs[8];
    u64    count       = (u64)(sizeof(addrs) / sizeof(addrs[0]));
    u32    granularity = 0u;
    AD_ZERO_BUF(addrs, sizeof(addrs));

    u32 ret = fn_gww(AD_WRITE_WATCH_FLAG_RESET, buf, reg_size, addrs, &count, &granularity);
    if (ret == 0u) {
        if (count != 1u) suspicious = 1;    // 0 = write was suppressed, >1 = extra writer
    }

    // ── Test 2: write nothing, expect count == 0 ────────────────────────────
    AD_ZERO_BUF(addrs, sizeof(addrs));
    count       = (u64)(sizeof(addrs) / sizeof(addrs[0]));
    granularity = 0u;

    AD_LFENCE();
    AD_MFENCE();
    AD_BARRIER();

    ret = fn_gww(0u, buf, reg_size, addrs, &count, &granularity);
    if (ret == 0u && count > 0u) {
        suspicious = 1;     // Something wrote without our permission
    }

    // Free allocation
    void* free_base = buf;
    u64   free_size = 0ULL;
    AD_SYSCALL4(
        s_ssn_free,
        AD_CURRENT_PROCESS,
        &free_base,
        &free_size,
        (u64)AD_MEM_RELEASE
    );

    return suspicious;
}

#else  // Non-MSVC stub
ANTIDEBUG_INLINE b32 ad_write_watch_check(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_WRITE_WATCH_H