// ===== file: antidebug/checks/threads/orphan_threads.h =====
//
// Orphan Thread Detection — find threads whose start address is not
// inside any legitimately loaded module.
//
// On a clean process, every thread's StartAddress (the RIP at thread
// entry, before any user code runs) is in one of:
//
//   * Our own EXE image        (main thread via RtlUserThreadStart)
//   * ntdll.dll                (worker pool / loader helpers)
//   * kernel32.dll             (some system helpers)
//   * Any legitimately loaded DLL's .text
//
// An INJECTED thread — CreateRemoteThread / NtCreateThreadEx from a
// debugger, DBI framework, or loader — usually has its StartAddress
// pointing to:
//
//   * A manually-mapped DLL in private RWX memory (absent from PEB.Ldr)
//   * A heap-allocated shellcode buffer
//   * A JIT code cache (Frida, DynamoRIO, Pin)
//
// Implementation path: Toolhelp32 thread enumeration (kernel32, no
// LoadLibrary needed) + NtQueryInformationThread(class 9) for the
// Win32 start address. Toolhelp32 is documented, portable, and doesn't
// depend on fragile SYSTEM_PROCESS_INFORMATION offsets that shift
// between Windows builds.
//
#ifndef ANTIDEBUG_ORPHAN_THREADS_H
#define ANTIDEBUG_ORPHAN_THREADS_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"
#include "hide_thread.h"   // reuse AD_STRENC_NtQueryInformationThread macro

#ifdef _MSC_VER

#define AD_OT_MAX_MODULES 128u
#define AD_OT_MAX_THREADS 256u

typedef struct {
    u8* base;
    u32 size;
} ad_ot_module_t;

typedef struct {
    u32   tid;
    void* start_addr;
    b32   orphan;
} ad_ot_thread_t;

typedef struct {
    u32              module_count;
    ad_ot_module_t   modules[AD_OT_MAX_MODULES];
    u32              thread_count;
    u32              orphan_count;
    ad_ot_thread_t   threads[AD_OT_MAX_THREADS];
} ad_ot_result_t;

// --- kernel32 Toolhelp32 + OpenThread / CloseHandle imports -----------------
// We use declspec imports because Toolhelp32 is the canonical cross-version
// path for own-thread enumeration. Hiding the imports via api_hash would
// add complexity for little gain — Toolhelp32 is present on every NT since
// Windows 2000.
__declspec(dllimport) void* __stdcall CreateToolhelp32Snapshot(unsigned long dwFlags, unsigned long th32ProcessID);
__declspec(dllimport) void* __stdcall OpenThread(unsigned long dwDesiredAccess, int bInheritHandle, unsigned long dwThreadId);
__declspec(dllimport) int   __stdcall CloseHandle(void* hObject);

typedef struct {
    unsigned long  dwSize;
    unsigned long  cntUsage;
    unsigned long  th32ThreadID;
    unsigned long  th32OwnerProcessID;
    long           tpBasePri;
    long           tpDeltaPri;
    unsigned long  dwFlags;
} AD_OT_THREADENTRY32;

__declspec(dllimport) int __stdcall Thread32First(void* hSnapshot, AD_OT_THREADENTRY32* lpte);
__declspec(dllimport) int __stdcall Thread32Next (void* hSnapshot, AD_OT_THREADENTRY32* lpte);

#define AD_OT_TH32CS_SNAPTHREAD       0x00000004
#define AD_OT_THREAD_QUERY_INFORMATION 0x0040

// --- PEB.Ldr walk → collect module ranges -----------------------------------
ANTIDEBUG_INLINE void ad_ot_collect_modules(ad_ot_result_t* r) {
    r->module_count = 0u;
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return;
    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return;

    u8* head  = ldr + 0x10;
    u8* entry = *(u8**)head;
    u32 walk = 0;
    while (entry != head && walk < AD_OT_MAX_MODULES && r->module_count < AD_OT_MAX_MODULES) {
        walk++;
        void* mod_base = *(void**)(entry + 0x30);
        u32   mod_size = *(u32*)(entry + 0x40);
        if (mod_base && mod_size) {
            r->modules[r->module_count].base = (u8*)mod_base;
            r->modules[r->module_count].size = mod_size;
            r->module_count++;
        }
        entry = *(u8**)entry;
    }
}

ANTIDEBUG_INLINE b32 ad_ot_addr_in_any_module(const ad_ot_result_t* r, u8* addr) {
    u32 i;
    for (i = 0; i < r->module_count; i++) {
        u8* b = r->modules[i].base;
        if (addr >= b && addr < b + r->modules[i].size) return 1;
    }
    return 0;
}

// Query ThreadQuerySetWin32StartAddress (class 9) on a thread handle.
// Returns the resolved start address, or 0 on failure.
ANTIDEBUG_INLINE void* ad_ot_query_start(void* hThread) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtQueryInformationThread, 25);
    if (s_ssn == AD_SSN_FAILED) return 0;

    u64 start = 0;
    u32 ret_len = 0;
    ad_ntstatus_t st = AD_SYSCALL5(s_ssn,
        hThread,
        (u64)9,                // ThreadQuerySetWin32StartAddress
        &start,
        (u64)sizeof(start),
        &ret_len);
    if (!AD_NT_SUCCESS(st)) return 0;
    return (void*)start;
}

// Main scan — enumerate via Toolhelp32, query StartAddress per handle,
// classify against module ranges.
ANTIDEBUG_INLINE void ad_ot_scan(ad_ot_result_t* out) {
    u32 k;
    for (k = 0; k < (u32)sizeof(*out); k++)
        ((volatile u8*)out)[k] = 0;

    ad_ot_collect_modules(out);
    if (out->module_count == 0u) return;

    u32 our_pid = (u32)(u64)__readgsqword(0x40);

    void* snap = CreateToolhelp32Snapshot(AD_OT_TH32CS_SNAPTHREAD, 0);
    if (snap == 0 || snap == (void*)(unsigned long long)-1) return;

    AD_OT_THREADENTRY32 te;
    AD_ZERO_BUF(&te, sizeof(te));
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != our_pid) continue;
            if (out->thread_count >= AD_OT_MAX_THREADS) break;

            void* ht = OpenThread(AD_OT_THREAD_QUERY_INFORMATION, 0, te.th32ThreadID);
            if (!ht) continue;

            void* start = ad_ot_query_start(ht);
            CloseHandle(ht);

            out->threads[out->thread_count].tid        = te.th32ThreadID;
            out->threads[out->thread_count].start_addr = start;

            b32 inside = (b32)(start != 0
                              && ad_ot_addr_in_any_module(out, (u8*)start));
            out->threads[out->thread_count].orphan = (b32)(!inside);
            if (!inside) out->orphan_count++;
            out->thread_count++;

        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
}

// Boolean wrapper.
ANTIDEBUG_INLINE b32 ad_orphan_thread_check(void) {
    ad_ot_result_t r;
    ad_ot_scan(&r);
    return (b32)(r.orphan_count > 0u);
}

ANTIDEBUG_INLINE u32 ad_orphan_thread_count(void) {
    ad_ot_result_t r;
    ad_ot_scan(&r);
    return r.orphan_count;
}

#else  // !_MSC_VER
typedef struct { int _unused; } ad_ot_result_t;
ANTIDEBUG_INLINE void ad_ot_scan(ad_ot_result_t* r) { (void)r; }
ANTIDEBUG_INLINE b32  ad_orphan_thread_check(void) { return 0; }
ANTIDEBUG_INLINE u32  ad_orphan_thread_count(void) { return 0u; }
#endif // _MSC_VER

#endif // ANTIDEBUG_ORPHAN_THREADS_H
