// ===== file: antidebug/checks/debug/window_scan.h =====
//
// Detect debuggers via window enumeration, ODS timing, and IFEO registry.
//
// Three independent checks:
//
//   1. ad_find_debugger_window()     -- FindWindowA for known debugger classes
//   2. ad_output_debug_string_timing() -- RDTSC around OutputDebugStringA
//   3. ad_ifeo_debugger_check()      -- Image File Execution Options "Debugger"
//   4. ad_window_scan_master()       -- weighted composite (6 + 4 + 8)
//
// All API resolution goes through ad_resolve_api() (hash-based PEB walk).
// No CRT, no static imports, no string literals in .rdata.
//
#ifndef ANTIDEBUG_WINDOW_SCAN_H
#define ANTIDEBUG_WINDOW_SCAN_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/api_hash.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// advapi32.dll module hash helper (built char-by-char, no .rdata string)
// ---------------------------------------------------------------------------
#ifndef AD_HASH_ADVAPI32
#define AD_HASH_ADVAPI32  ad_hash_module_advapi32()
ANTIDEBUG_INLINE u32 ad_hash_module_advapi32(void) {
    static u32 h = 0;
    if (!h) {
        u16 w[13];
        w[0]='a'; w[1]='d'; w[2]='v'; w[3]='a'; w[4]='p';
        w[5]='i'; w[6]='3'; w[7]='2'; w[8]='.'; w[9]='d';
        w[10]='l'; w[11]='l'; w[12]=0;
        h = ad_hash_wstr(w, 12);
    }
    return h;
}
#endif

// ---------------------------------------------------------------------------
// Function pointer typedefs (no windows.h)
// ---------------------------------------------------------------------------
typedef void* (__stdcall *FN_FindWindowA)(const char*, const char*);
typedef int   (__stdcall *FN_GetWindowTextA)(void*, char*, int);
typedef void  (__stdcall *FN_OutputDebugStringA)(const char*);
typedef long  (__stdcall *FN_RegOpenKeyExA)(void*, const char*, u32, u32, void**);
typedef long  (__stdcall *FN_RegQueryValueExA)(void*, const char*, u32*, u32*, u8*, u32*);
typedef long  (__stdcall *FN_RegCloseKey)(void*);

// ---------------------------------------------------------------------------
// ad_ws_tolower -- single-char ASCII lowercase without CRT
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE char ad_ws_tolower(char c) {
    if (c >= 'A' && c <= 'Z') return (char)(c + 32);
    return c;
}

// ---------------------------------------------------------------------------
// ad_ws_contains_ci -- case-insensitive substring search (no CRT)
// Returns 1 if needle is found inside haystack.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_ws_contains_ci(const char* haystack, const char* needle) {
    u32 hi, ni;
    if (!haystack || !needle) return 0;
    for (hi = 0; haystack[hi]; hi++) {
        b32 match = 1;
        for (ni = 0; needle[ni]; ni++) {
            if (!haystack[hi + ni]) { match = 0; break; }
            if (ad_ws_tolower(haystack[hi + ni]) != ad_ws_tolower(needle[ni])) {
                match = 0;
                break;
            }
        }
        if (match && needle[ni] == '\0') return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// ad_ws_debugger_attached -- check if a debugger is attached to OUR process.
//
// Two independent checks (both must fail for "not attached"):
//   1. PEB.BeingDebugged (offset 0x02 from GS:[0x60]) -- fast but clearable
//   2. NtQueryInformationProcess(ProcessDebugPort=7) -- kernel-level, harder
//      to fake without a kernel driver
//
// Returns 1 if either check says we are being debugged.
// Returns 1 if we cannot determine (fail secure).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_ws_debugger_attached(void) {
    // Check 1: PEB.BeingDebugged
    u8* peb = (u8*)__readgsqword(0x60);
    if (peb) {
        u8 being_debugged = *(volatile u8*)(peb + 0x02);
        if (being_debugged) return 1;
    }

    // Check 2: ProcessDebugPort via NtQueryInformationProcess
    // Resolve SSN for NtQueryInformationProcess
    static u16 s_ssn_qip = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qip, NtQueryInformationProcess, 26);
    if (s_ssn_qip == AD_SSN_FAILED) return 1;  // fail secure

    u64 debug_port = 0;
    u32 ret_len = 0;
    ad_ntstatus_t st = AD_SYSCALL5(s_ssn_qip,
        AD_CURRENT_PROCESS,
        (u64)AD_PROCESS_DEBUG_PORT,  // ProcessDebugPort = 7
        &debug_port,
        (u64)sizeof(debug_port),
        &ret_len);

    if (!AD_NT_SUCCESS(st)) return 1;  // fail secure: cannot determine
    if (debug_port != 0) return 1;

    return 0;
}

// ---------------------------------------------------------------------------
// 1. ad_find_debugger_window
//
// Resolve FindWindowA from user32.dll, probe known debugger window classes.
// All class name strings are built char-by-char on the stack.
//
// FALSE-POSITIVE FIX: After finding a debugger window, verify the debugger
// is actually attached to OUR process via PEB.BeingDebugged and
// ProcessDebugPort. A debugger open on the machine but not attached to us
// should not trigger this check.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_find_debugger_window(void) {
    FN_FindWindowA pFindWindowA = (FN_FindWindowA)
        ad_resolve_api(AD_HASH_USER32, AD_HASH("FindWindowA"));
    if (!pFindWindowA) return 0;

    AD_BARRIER();

    b32 window_found = 0;

    // -- "x64dbg" (6 chars) --
    if (!window_found) {
        char cls[7];
        cls[0]='x'; cls[1]='6'; cls[2]='4'; cls[3]='d';
        cls[4]='b'; cls[5]='g'; cls[6]='\0';
        if (pFindWindowA(cls, (const char*)0)) window_found = 1;
    }

    // -- "OLLYDBG" (7 chars) --
    if (!window_found) {
        char cls[8];
        cls[0]='O'; cls[1]='L'; cls[2]='L'; cls[3]='Y';
        cls[4]='D'; cls[5]='B'; cls[6]='G'; cls[7]='\0';
        if (pFindWindowA(cls, (const char*)0)) window_found = 1;
    }

    // -- "ID" (2 chars) -- IDA disassembly view
    if (!window_found) {
        char cls[3];
        cls[0]='I'; cls[1]='D'; cls[2]='\0';
        if (pFindWindowA(cls, (const char*)0)) window_found = 1;
    }

    // -- "idaview" (7 chars) --
    if (!window_found) {
        char cls[8];
        cls[0]='i'; cls[1]='d'; cls[2]='a'; cls[3]='v';
        cls[4]='i'; cls[5]='e'; cls[6]='w'; cls[7]='\0';
        if (pFindWindowA(cls, (const char*)0)) window_found = 1;
    }

    // -- "WinDbgFrameClass" (16 chars) --
    if (!window_found) {
        char cls[17];
        cls[0]='W'; cls[1]='i';  cls[2]='n';  cls[3]='D';
        cls[4]='b'; cls[5]='g';  cls[6]='F';  cls[7]='r';
        cls[8]='a'; cls[9]='m';  cls[10]='e'; cls[11]='C';
        cls[12]='l'; cls[13]='a'; cls[14]='s'; cls[15]='s';
        cls[16]='\0';
        if (pFindWindowA(cls, (const char*)0)) window_found = 1;
    }

    // -- "Qt5QWindowIcon" (14 chars) -- x64dbg / IDA Qt windows
    // If found, read the title and check for debugger-related substrings.
    if (!window_found) {
        char cls[15];
        cls[0]='Q'; cls[1]='t';  cls[2]='5';  cls[3]='Q';
        cls[4]='W'; cls[5]='i';  cls[6]='n';  cls[7]='d';
        cls[8]='o'; cls[9]='w';  cls[10]='I'; cls[11]='c';
        cls[12]='o'; cls[13]='n'; cls[14]='\0';

        void* hwnd = pFindWindowA(cls, (const char*)0);
        if (hwnd) {
            FN_GetWindowTextA pGetWindowTextA = (FN_GetWindowTextA)
                ad_resolve_api(AD_HASH_USER32, AD_HASH("GetWindowTextA"));
            if (pGetWindowTextA) {
                char title[256];
                AD_ZERO_BUF(title, sizeof(title));
                int len = pGetWindowTextA(hwnd, title, 255);
                if (len > 0) {
                    // Build needle strings on stack
                    char n_dbg[4];
                    n_dbg[0]='d'; n_dbg[1]='b'; n_dbg[2]='g'; n_dbg[3]='\0';

                    char n_ida[4];
                    n_ida[0]='i'; n_ida[1]='d'; n_ida[2]='a'; n_ida[3]='\0';

                    char n_debug[6];
                    n_debug[0]='d'; n_debug[1]='e'; n_debug[2]='b';
                    n_debug[3]='u'; n_debug[4]='g'; n_debug[5]='\0';

                    if (ad_ws_contains_ci(title, n_dbg))   window_found = 1;
                    if (ad_ws_contains_ci(title, n_ida))   window_found = 1;
                    if (ad_ws_contains_ci(title, n_debug)) window_found = 1;
                }
            }
        }
    }

    // Cross-check via ProcessDebugObjectHandle (class 30) — harder to fake
    // than PEB.BeingDebugged or ProcessDebugPort. ScyllaHide typically
    // patches classes 7 and 31 but often misses class 30.
    if (window_found) {
        static u16 s_ssn_qip2 = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_ssn_qip2, NtQueryInformationProcess, 26);
        if (s_ssn_qip2 == AD_SSN_FAILED) return 1;

        u64 dbg_obj = 0;
        u32 rl = 0;
        // ProcessDebugObjectHandle = 30
        ad_ntstatus_t st = AD_SYSCALL5(s_ssn_qip2,
            AD_CURRENT_PROCESS, (u64)30,
            &dbg_obj, (u64)sizeof(dbg_obj), &rl);
        // STATUS_PORT_NOT_SET (0xC0000353) = no debug object = clean
        if (AD_NT_SUCCESS(st) && dbg_obj != 0) return 1;
        // Also check DebugPort as fallback
        u64 dbg_port = 0;
        st = AD_SYSCALL5(s_ssn_qip2,
            AD_CURRENT_PROCESS, (u64)AD_PROCESS_DEBUG_PORT,
            &dbg_port, (u64)sizeof(dbg_port), &rl);
        if (AD_NT_SUCCESS(st) && dbg_port != 0) return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 2. ad_output_debug_string_timing
//
// OutputDebugStringA takes 5000+ RDTSC cycles under a debugger (the kernel
// dispatches the string through the debug subsystem). Without a debugger
// it returns almost immediately (< 500 cycles).
//
// We run 3 iterations and take the minimum delta to filter interrupt noise.
// Threshold: 3000 cycles.
// ---------------------------------------------------------------------------
#define AD_ODS_THRESHOLD  3000ULL
#define AD_ODS_ITERATIONS 3

ANTIDEBUG_INLINE b32 ad_output_debug_string_timing(void) {
    FN_OutputDebugStringA pODS = (FN_OutputDebugStringA)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("OutputDebugStringA"));
    if (!pODS) return 0;

    // Build a dummy string on the stack
    char dummy[8];
    dummy[0]='t'; dummy[1]='e'; dummy[2]='s'; dummy[3]='t';
    dummy[4]='\0';

    u64 min_delta = (u64)(~0ULL);
    u32 iter;

    for (iter = 0; iter < AD_ODS_ITERATIONS; iter++) {
        AD_LFENCE();
        AD_BARRIER();
        u64 t0 = __rdtsc();
        AD_LFENCE();

        pODS(dummy);

        AD_LFENCE();
        AD_BARRIER();
        u64 t1 = __rdtsc();
        AD_LFENCE();

        u64 delta = t1 - t0;
        if (delta < min_delta) min_delta = delta;
    }

    // FALSE-POSITIVE GUARD: ODS timing can be slow for reasons other than
    // debugging (e.g. a third-party debugger open but not attached to us,
    // or DbgPrint hooks from monitoring tools). Only flag if the debug port
    // is actually active for our process.
    if (min_delta > AD_ODS_THRESHOLD) {
        // Cross-check: slow ODS can happen without a debugger (monitoring tools).
        // Confirm via ProcessDebugObjectHandle (class 30) before scoring.
        static u16 s_ssn_qip3 = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_ssn_qip3, NtQueryInformationProcess, 26);
        if (s_ssn_qip3 == AD_SSN_FAILED) return 1;

        u64 dbg_obj = 0;
        u32 rl = 0;
        ad_ntstatus_t st = AD_SYSCALL5(s_ssn_qip3,
            AD_CURRENT_PROCESS, (u64)30,
            &dbg_obj, (u64)sizeof(dbg_obj), &rl);
        if (AD_NT_SUCCESS(st) && dbg_obj != 0) return 1;

        u64 dbg_port = 0;
        st = AD_SYSCALL5(s_ssn_qip3,
            AD_CURRENT_PROCESS, (u64)AD_PROCESS_DEBUG_PORT,
            &dbg_port, (u64)sizeof(dbg_port), &rl);
        if (AD_NT_SUCCESS(st) && dbg_port != 0) return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 3. ad_ifeo_debugger_check
//
// Check HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
//   Image File Execution Options\<our_exe_name>
// for a "Debugger" value. If it exists and is non-empty, a debugger is
// configured to auto-attach at process creation.
//
// Our exe name is extracted from PEB->ProcessParameters->ImagePathName
// (last component after the final backslash).
//
// API resolution: RegOpenKeyExA + RegQueryValueExA + RegCloseKey from
// advapi32.dll via ad_resolve_api(). advapi32 is loaded on-demand via
// LoadLibraryA from kernel32 if not already in the module list.
// ---------------------------------------------------------------------------

// HKEY_LOCAL_MACHINE = 0x80000002
#define AD_HKLM  ((void*)(u64)0x80000002UL)
// KEY_READ = 0x20019
#define AD_KEY_READ 0x20019UL

ANTIDEBUG_INLINE b32 ad_ifeo_debugger_check(void) {
    // ------------------------------------------------------------------
    // Step 1: Extract our exe name from PEB
    // ------------------------------------------------------------------
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;

    // PEB->ProcessParameters at offset 0x20
    u8* params = *(u8**)(peb + 0x20);
    if (!params) return 0;

    // RTL_USER_PROCESS_PARAMETERS.ImagePathName is a UNICODE_STRING at +0x60
    // UNICODE_STRING: u16 Length, u16 MaxLen, u32 _pad, u16* Buffer
    u16  img_len_bytes = *(u16*)(params + 0x60);
    u16* img_buf       = *(u16**)(params + 0x68);
    if (!img_buf || img_len_bytes < 4u) return 0;

    u32 img_chars = (u32)(img_len_bytes / 2u);

    // Find last backslash to isolate the exe filename
    u32 last_slash = 0;
    u32 ci;
    for (ci = 0; ci < img_chars; ci++) {
        if (img_buf[ci] == (u16)'\\') last_slash = ci + 1u;
    }

    // Convert exe name from wide to ASCII on the stack
    char exe_name[64];
    u32 elen = 0;
    for (ci = last_slash; ci < img_chars && elen < 63u; ci++) {
        u16 wc = img_buf[ci];
        if (wc == 0) break;
        exe_name[elen++] = (char)(wc & 0xFF);
    }
    exe_name[elen] = '\0';

    if (elen == 0) return 0;

    // ------------------------------------------------------------------
    // Step 2: Ensure advapi32.dll is loaded
    // ------------------------------------------------------------------
    // Try to find advapi32 in already-loaded modules first
    u8* advapi_base = ad_find_module_by_hash(AD_HASH_ADVAPI32);
    if (!advapi_base) {
        // advapi32 not loaded yet -- load it via LoadLibraryA
        typedef void* (__stdcall *FN_LoadLibraryA)(const char*);
        FN_LoadLibraryA pLoadLibraryA = (FN_LoadLibraryA)
            ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("LoadLibraryA"));
        if (pLoadLibraryA) {
            char dll[13];
            dll[0]='a'; dll[1]='d'; dll[2]='v'; dll[3]='a';
            dll[4]='p'; dll[5]='i'; dll[6]='3'; dll[7]='2';
            dll[8]='.'; dll[9]='d'; dll[10]='l'; dll[11]='l';
            dll[12]='\0';
            pLoadLibraryA(dll);
        }
    }

    // ------------------------------------------------------------------
    // Step 3: Resolve registry APIs from advapi32
    // ------------------------------------------------------------------
    FN_RegOpenKeyExA pRegOpen = (FN_RegOpenKeyExA)
        ad_resolve_api(AD_HASH_ADVAPI32, AD_HASH("RegOpenKeyExA"));
    FN_RegQueryValueExA pRegQuery = (FN_RegQueryValueExA)
        ad_resolve_api(AD_HASH_ADVAPI32, AD_HASH("RegQueryValueExA"));
    FN_RegCloseKey pRegClose = (FN_RegCloseKey)
        ad_resolve_api(AD_HASH_ADVAPI32, AD_HASH("RegCloseKey"));

    if (!pRegOpen || !pRegQuery || !pRegClose) return 0;

    // ------------------------------------------------------------------
    // Step 4: Build the IFEO registry path on the stack
    // "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\"
    // + exe_name
    // ------------------------------------------------------------------
    // Base path (78 chars without exe name)
    char path[200];
    AD_ZERO_BUF(path, sizeof(path));

    // "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
    u32 pi = 0;
    // S O F T W A R E
    path[pi++]='S'; path[pi++]='O'; path[pi++]='F'; path[pi++]='T';
    path[pi++]='W'; path[pi++]='A'; path[pi++]='R'; path[pi++]='E';
    path[pi++]='\\';
    // M i c r o s o f t
    path[pi++]='M'; path[pi++]='i'; path[pi++]='c'; path[pi++]='r';
    path[pi++]='o'; path[pi++]='s'; path[pi++]='o'; path[pi++]='f';
    path[pi++]='t';
    path[pi++]='\\';
    // W i n d o w s   N T
    path[pi++]='W'; path[pi++]='i'; path[pi++]='n'; path[pi++]='d';
    path[pi++]='o'; path[pi++]='w'; path[pi++]='s'; path[pi++]=' ';
    path[pi++]='N'; path[pi++]='T';
    path[pi++]='\\';
    // C u r r e n t V e r s i o n
    path[pi++]='C'; path[pi++]='u'; path[pi++]='r'; path[pi++]='r';
    path[pi++]='e'; path[pi++]='n'; path[pi++]='t'; path[pi++]='V';
    path[pi++]='e'; path[pi++]='r'; path[pi++]='s'; path[pi++]='i';
    path[pi++]='o'; path[pi++]='n';
    path[pi++]='\\';
    // I m a g e   F i l e   E x e c u t i o n   O p t i o n s
    path[pi++]='I'; path[pi++]='m'; path[pi++]='a'; path[pi++]='g';
    path[pi++]='e'; path[pi++]=' '; path[pi++]='F'; path[pi++]='i';
    path[pi++]='l'; path[pi++]='e'; path[pi++]=' '; path[pi++]='E';
    path[pi++]='x'; path[pi++]='e'; path[pi++]='c'; path[pi++]='u';
    path[pi++]='t'; path[pi++]='i'; path[pi++]='o'; path[pi++]='n';
    path[pi++]=' '; path[pi++]='O'; path[pi++]='p'; path[pi++]='t';
    path[pi++]='i'; path[pi++]='o'; path[pi++]='n'; path[pi++]='s';
    path[pi++]='\\';

    // Append exe name
    for (ci = 0; ci < elen && pi < 198u; ci++) {
        path[pi++] = exe_name[ci];
    }
    path[pi] = '\0';

    // ------------------------------------------------------------------
    // Step 5: Open and query
    // ------------------------------------------------------------------
    void* hKey = (void*)0;
    long result = pRegOpen(AD_HKLM, path, 0, AD_KEY_READ, &hKey);
    if (result != 0 || !hKey) return 0;

    // Query "Debugger" value
    char val_name[9];
    val_name[0]='D'; val_name[1]='e'; val_name[2]='b'; val_name[3]='u';
    val_name[4]='g'; val_name[5]='g'; val_name[6]='e'; val_name[7]='r';
    val_name[8]='\0';

    u32 val_type = 0;
    u8  val_data[4];  // We only need to know if it exists and is non-empty
    u32 val_size = (u32)sizeof(val_data);

    result = pRegQuery(hKey, val_name, (u32*)0, &val_type, val_data, &val_size);
    pRegClose(hKey);

    // ERROR_SUCCESS = 0, ERROR_MORE_DATA = 234 (value exists but buffer too small)
    // Either way, the "Debugger" value exists.
    if (result == 0 || result == 234) {
        // Check that the value has actual content (not just empty string)
        if (val_size > 1u) return 1;
        if (result == 234) return 1;  // buffer too small = definitely non-empty
    }

    return 0;
}

// ---------------------------------------------------------------------------
// 4. ad_window_scan_master -- composite score
//
// Weights:
//   find_debugger_window:       6
//   output_debug_string_timing: 4
//   ifeo_debugger_check:        8
// ---------------------------------------------------------------------------
NOINLINE u32 ad_window_scan_master(void) {
    u32 score = 0u;

    { b32 v = ad_find_debugger_window();       if (v) score += 6u; }
    AD_BARRIER();
    { b32 v = ad_output_debug_string_timing();  if (v) score += 4u; }
    AD_BARRIER();
    { b32 v = ad_ifeo_debugger_check();         if (v) score += 8u; }

    return score;
}

#else
// Non-MSVC stubs
ANTIDEBUG_INLINE b32 ad_find_debugger_window(void)        { return 0; }
ANTIDEBUG_INLINE b32 ad_output_debug_string_timing(void)  { return 0; }
ANTIDEBUG_INLINE b32 ad_ifeo_debugger_check(void)         { return 0; }
ANTIDEBUG_INLINE u32 ad_window_scan_master(void)           { return 0u; }
#endif // _MSC_VER

#endif // ANTIDEBUG_WINDOW_SCAN_H
