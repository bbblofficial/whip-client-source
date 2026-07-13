// ===== file: antidebug/checks/advanced/exception_rip_anchor.h =====
//
// Exception RIP Anchor — DBI / code-cache detector.
//
// Idea
// ----
// We deliberately raise an EXCEPTION_ACCESS_VIOLATION at a known site inside
// THIS function. In the SEH filter we read
//   ExceptionRecord->ExceptionAddress
// — the kernel-reported RIP at the moment the fault was raised.
//
// On a clean system that RIP must lie inside our own PE image, between
// ImageBase and ImageBase + SizeOfImage. Dynamic Binary Instrumentation
// frameworks (Intel Pin, DynamoRIO, Frida-stalker, QBDI…) do NOT execute the
// original code: they JIT-translate basic blocks into a private code cache
// and run the *translated* copy. When that copy faults, the kernel reports
// the RIP **inside the cache region** — far outside our image.
//
// The same applies to certain hypervisor-level instrumentation that re-maps
// guest code at a shadow address. Both give an immediate hard positive with
// no false positives on bare metal.
//
// We deliberately use a wild pointer rather than calling a faulting helper:
// the fault must originate from an instruction emitted directly into this
// function, not a call site (calls would land us in a callee that the JIT
// could legitimately cache without instrumenting our caller).
//
#ifndef ANTIDEBUG_EXCEPTION_RIP_ANCHOR_H
#define ANTIDEBUG_EXCEPTION_RIP_ANCHOR_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER

#ifndef EXCEPTION_EXECUTE_HANDLER
#define EXCEPTION_EXECUTE_HANDLER      1
#define EXCEPTION_CONTINUE_SEARCH      0
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#endif
#ifndef GetExceptionInformation
void* __cdecl _exception_info(void);
#define GetExceptionInformation() (_exception_info())
#endif

// Minimal EXCEPTION_RECORD / EXCEPTION_POINTERS — match veh_decoy.h layout
typedef struct {
    u32   ExceptionCode;
    u32   ExceptionFlags;
    void* ExceptionRecord;
    void* ExceptionAddress;
    u32   NumberParameters;
    u32   _pad;
    u64   ExceptionInformation[15];
} AD_RIP_EXC_RECORD;

typedef struct {
    AD_RIP_EXC_RECORD* ExceptionRecord;
    void*              ContextRecord;
} AD_RIP_EXC_POINTERS;

// Returns 1 if the faulting RIP reported by SEH is OUTSIDE our PE image.
ANTIDEBUG_INLINE b32 ad_exception_rip_anchor_check(void) {
    // ----- Resolve our own image bounds via PEB.ImageBaseAddress -----------
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* image_base = *(u8**)(peb + 0x10);
    if (!image_base) return 0;
    if (*(u16*)image_base != 0x5A4D) return 0;  // 'MZ'

    u32 pe_off = *(u32*)(image_base + 0x3C);
    if (pe_off > 0x1000u) return 0;
    u8* pe = image_base + pe_off;
    if (*(u32*)pe != 0x00004550u) return 0;     // 'PE\0\0'

    // OptionalHeader64.SizeOfImage at offset 56 inside the optional header.
    // OptionalHeader starts at pe + 24.
    u32 size_of_image = *(u32*)(pe + 24 + 56);
    if (size_of_image < 0x1000u) return 0;
    u8* image_end = image_base + size_of_image;

    // ----- Trigger AV and capture ExceptionAddress in the SEH filter -------
    volatile void* fault_rip = 0;

    __try {
        // The next read MUST be the actual faulting instruction so the
        // kernel-reported RIP points into THIS function body (and therefore
        // into our .text on a clean system).
        volatile u8* bad = (volatile u8*)(u64)0xCAFEBABEu;
        volatile u8 sink = *bad;
        AD_UNUSED(sink);
    }
    __except (
        fault_rip = ((AD_RIP_EXC_POINTERS*)GetExceptionInformation())
                        ->ExceptionRecord->ExceptionAddress,
        EXCEPTION_EXECUTE_HANDLER
    ) {
        // handler body intentionally empty — work was done in the filter
    }

    if (!fault_rip) return 0;  // no info → fail open
    u8* rip = (u8*)fault_rip;

    // Clean: RIP is inside our main PE image.
    if (rip >= image_base && rip < image_end) return 0;

    // DLL context: the faulting code may live in our DLL, not the host EXE.
    // Walk PEB.Ldr.InLoadOrderModuleList to check if RIP falls inside ANY
    // legitimately loaded module. DBI code caches are private allocations
    // that do NOT appear in the module list.
    {
        u8* ldr = *(u8**)(peb + 0x18);         // PEB.Ldr
        u8* list_head = ldr + 0x10;             // InLoadOrderModuleList
        u8* entry = *(u8**)list_head;
        u32 walk = 0;
        while (entry != list_head && walk < 200u) {
            void* mod_base = *(void**)(entry + 0x30);   // DllBase
            u32   mod_size = *(u32*)(entry + 0x40);      // SizeOfImage
            if (mod_base && mod_size) {
                u8* mod_start = (u8*)mod_base;
                u8* mod_end   = mod_start + mod_size;
                if (rip >= mod_start && rip < mod_end)
                    return 0;   // RIP in a known loaded module → clean
            }
            entry = *(u8**)entry;
            walk++;
        }
    }

    // RIP outside ALL loaded modules → JIT code cache, shadow page, or DBI.
    return 1;
}

#endif // _MSC_VER

#ifndef _MSC_VER
ANTIDEBUG_INLINE b32 ad_exception_rip_anchor_check(void) { return 0; }
#endif

#endif // ANTIDEBUG_EXCEPTION_RIP_ANCHOR_H
