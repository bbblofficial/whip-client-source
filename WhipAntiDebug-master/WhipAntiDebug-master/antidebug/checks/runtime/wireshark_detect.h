// ===== file: antidebug/checks/runtime/wireshark_detect.h =====
//
// Wireshark / Npcap / WinPcap packet-capture stack detection.
//
// Reverse engineers commonly pair Wireshark (or tshark / dumpcap) with a
// debugger to capture network traffic during analysis. The existing
// process_sig_scan.h catches wireshark.exe and dumpcap.exe by FNV-1a hash
// of the image name — trivially defeated by renaming the binary or
// building from source (wireshark-master) with a custom target name.
//
// This check is NAME-INDEPENDENT. It probes four independent environmental
// signals that survive any rename:
//
//   bit 0  AD_WS_MODULE       wpcap.dll / npcap.dll / Packet.dll loaded in
//                             our own process (PEB.Ldr walk). Triggers when
//                             extcap tooling or an injected capture agent
//                             has pulled the stack into us.
//
//   bit 1  AD_WS_WINDOW       Top-level window whose title contains
//                             "Wireshark" (EnumWindows + GetWindowTextW
//                             substring scan). Title is hardcoded in the
//                             Wireshark source (ui/qt/main_window.cpp).
//
//   bit 2  AD_WS_REGKEY       HKLM\SOFTWARE\Wireshark exists. Installer
//                             creates this key. Survives exe rename.
//
//   bit 3  AD_WS_NPCAP_SVC    HKLM\SYSTEM\CurrentControlSet\Services\npcap
//                             or ...\npf exists. Packet capture driver is
//                             registered. Strongest signal — Npcap is
//                             code-signed by Nmap.org and cannot be
//                             trivially renamed.
//
// Returns a u32 bitmask. 0 = clean. Any non-zero bit = suspicion; weight
// at the caller per bit (AD_WS_NPCAP_SVC is the most reliable).
//
#ifndef ANTIDEBUG_WIRESHARK_DETECT_H
#define ANTIDEBUG_WIRESHARK_DETECT_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/api_hash.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#if defined(_MSC_VER)

#define AD_WS_MODULE      0x01u
#define AD_WS_WINDOW      0x02u
#define AD_WS_REGKEY      0x04u
#define AD_WS_NPCAP_SVC   0x08u
#define AD_WS_PROCESS     0x10u
#define AD_WS_PARENT      0x20u
#define AD_WS_FOREGROUND  0x40u
#define AD_WS_RECENT      0x80u
#define AD_WS_HOOK_EVENT  0x100u

// Default "recent launch" window — 10 seconds (in 100ns units, FILETIME).
#ifndef AD_WS_RECENT_WINDOW_100NS
#define AD_WS_RECENT_WINDOW_100NS  (100000000ULL)   // 10 s
#endif

// ---------------------------------------------------------------------------
// Case-insensitive wide-char utilities (copied from suspicious_dlls.h pattern
// so this header is self-contained; inlines de-duplicate at link time).
// ---------------------------------------------------------------------------
static __forceinline u16 ad_ws_wlower(u16 c) {
    if (c >= (u16)'A' && c <= (u16)'Z') return (u16)(c + 32u);
    return c;
}

static __forceinline b32 ad_ws_wcontains_ci(
    const u16* hay, u32 hay_len,
    const u16* needle, u32 needle_len)
{
    if (needle_len == 0u || needle_len > hay_len) return 0;
    u32 limit = hay_len - needle_len;
    u32 i, j;
    for (i = 0u; i <= limit; i++) {
        b32 match = 1;
        for (j = 0u; j < needle_len; j++) {
            if (ad_ws_wlower(hay[i + j]) != ad_ws_wlower(needle[j])) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 1. Module scan — walk PEB.Ldr for wpcap / npcap / Packet DLLs.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_ws_module_loaded(void) {
    static const u16 w_wpcap[]  = {'w','p','c','a','p'};
    static const u16 w_npcap[]  = {'n','p','c','a','p'};
    static const u16 w_packet[] = {'p','a','c','k','e','t','.','d','l','l'};

    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + 0x18);
    if (!ldr) return 0;

    u8* head  = ldr + 0x10;
    u8* entry = *(u8**)head;

    u32 visited = 0u;
    while (entry != head && visited < 512u) {
        visited++;
        u16  name_len_bytes = *(u16*)(entry + 0x58);
        u16* name_buf       = *(u16**)(entry + 0x60);
        u32  name_chars     = (u32)(name_len_bytes / 2u);

        if (name_buf && name_chars > 0u) {
            if (ad_ws_wcontains_ci(name_buf, name_chars, w_wpcap,  5u)) return 1;
            if (ad_ws_wcontains_ci(name_buf, name_chars, w_npcap,  5u)) return 1;
            if (ad_ws_wcontains_ci(name_buf, name_chars, w_packet, 10u)) return 1;
        }
        entry = *(u8**)entry;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 2. Window-title scan — EnumWindows + GetWindowTextW; substring "Wireshark".
//
// Wireshark's main window title always contains the literal "Wireshark"
// (see wireshark-master/ui/qt/main_window.cpp — set via setWindowTitle()).
// ---------------------------------------------------------------------------
typedef int (__stdcall *FN_EnumWindowsProc)(void* hwnd, void* lparam);
typedef int (__stdcall *FN_EnumWindows)(FN_EnumWindowsProc, void*);
typedef int (__stdcall *FN_GetWindowTextW)(void*, u16*, int);

static int __stdcall ad_ws_enum_cb(void* hwnd, void* lparam) {
    static const u16 w_needle[] = {'W','i','r','e','s','h','a','r','k'};

    FN_GetWindowTextW pGet = (FN_GetWindowTextW)
        ad_resolve_api(AD_HASH_USER32, AD_HASH("GetWindowTextW"));
    if (!pGet) { *(volatile b32*)lparam = 0; return 1; }

    u16 buf[256];
    int len = pGet(hwnd, buf, 255);
    if (len > 0 && (u32)len < 256u) {
        if (ad_ws_wcontains_ci(buf, (u32)len, w_needle, 9u)) {
            *(volatile b32*)lparam = 1;
            return 0;  // stop enumeration
        }
    }
    return 1;  // continue
}

ANTIDEBUG_INLINE b32 ad_ws_window_present(void) {
    FN_EnumWindows pEnum = (FN_EnumWindows)
        ad_resolve_api(AD_HASH_USER32, AD_HASH("EnumWindows"));
    if (!pEnum) return 0;

    volatile b32 found = 0;
    pEnum(ad_ws_enum_cb, (void*)&found);
    return (b32)found;
}

// ---------------------------------------------------------------------------
// 3. Registry key probe — HKLM\SOFTWARE\Wireshark via RegOpenKeyExA.
// 4. Npcap service probe — HKLM\SYSTEM\CurrentControlSet\Services\npcap OR ..\npf
// ---------------------------------------------------------------------------
typedef long (__stdcall *FN_RegOpenKeyExA)(void*, const char*, u32, u32, void**);
typedef long (__stdcall *FN_RegCloseKey)(void*);
typedef void* (__stdcall *FN_LoadLibraryA)(const char*);

#ifndef AD_HKLM
#define AD_HKLM  ((void*)(u64)0x80000002UL)
#endif
#ifndef AD_KEY_READ
#define AD_KEY_READ 0x20019UL
#endif

ANTIDEBUG_INLINE b32 ad_ws_reg_key_exists(const char* path) {
    // Ensure advapi32 is loaded.
    static u32 s_hash_advapi = 0;
    if (!s_hash_advapi) {
        u16 w[13];
        w[ 0]='a'; w[ 1]='d'; w[ 2]='v'; w[ 3]='a'; w[ 4]='p';
        w[ 5]='i'; w[ 6]='3'; w[ 7]='2'; w[ 8]='.'; w[ 9]='d';
        w[10]='l'; w[11]='l'; w[12]=0;
        s_hash_advapi = ad_hash_wstr(w, 12);
    }

    u8* advapi = ad_find_module_by_hash(s_hash_advapi);
    if (!advapi) {
        FN_LoadLibraryA pLL = (FN_LoadLibraryA)
            ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("LoadLibraryA"));
        if (pLL) {
            char dll[13];
            dll[ 0]='a'; dll[ 1]='d'; dll[ 2]='v'; dll[ 3]='a';
            dll[ 4]='p'; dll[ 5]='i'; dll[ 6]='3'; dll[ 7]='2';
            dll[ 8]='.'; dll[ 9]='d'; dll[10]='l'; dll[11]='l';
            dll[12]=0;
            pLL(dll);
        }
    }

    FN_RegOpenKeyExA pOpen = (FN_RegOpenKeyExA)
        ad_resolve_api(s_hash_advapi, AD_HASH("RegOpenKeyExA"));
    FN_RegCloseKey pClose = (FN_RegCloseKey)
        ad_resolve_api(s_hash_advapi, AD_HASH("RegCloseKey"));
    if (!pOpen || !pClose) return 0;

    void* hKey = 0;
    long st = pOpen(AD_HKLM, path, 0, AD_KEY_READ, &hKey);
    if (st == 0 && hKey) {
        pClose(hKey);
        return 1;
    }
    return 0;
}

ANTIDEBUG_INLINE b32 ad_ws_wireshark_installed(void) {
    // "SOFTWARE\Wireshark" built on the stack — no .rdata literal.
    char p[18];
    p[ 0]='S'; p[ 1]='O'; p[ 2]='F'; p[ 3]='T'; p[ 4]='W';
    p[ 5]='A'; p[ 6]='R'; p[ 7]='E'; p[ 8]='\\';
    p[ 9]='W'; p[10]='i'; p[11]='r'; p[12]='e'; p[13]='s';
    p[14]='h'; p[15]='a'; p[16]='r'; p[17]='k';
    char pz[19]; u32 i; for (i = 0; i < 18u; i++) pz[i] = p[i]; pz[18] = 0;
    return ad_ws_reg_key_exists(pz);
}

ANTIDEBUG_INLINE b32 ad_ws_npcap_driver_installed(void) {
    // "SYSTEM\CurrentControlSet\Services\npcap"
    char np[41];
    u32 i = 0;
    np[i++]='S'; np[i++]='Y'; np[i++]='S'; np[i++]='T'; np[i++]='E'; np[i++]='M';
    np[i++]='\\';
    np[i++]='C'; np[i++]='u'; np[i++]='r'; np[i++]='r'; np[i++]='e';
    np[i++]='n'; np[i++]='t'; np[i++]='C'; np[i++]='o'; np[i++]='n';
    np[i++]='t'; np[i++]='r'; np[i++]='o'; np[i++]='l'; np[i++]='S';
    np[i++]='e'; np[i++]='t';
    np[i++]='\\';
    np[i++]='S'; np[i++]='e'; np[i++]='r'; np[i++]='v'; np[i++]='i';
    np[i++]='c'; np[i++]='e'; np[i++]='s';
    np[i++]='\\';
    np[i++]='n'; np[i++]='p'; np[i++]='c'; np[i++]='a'; np[i++]='p';
    np[i]=0;
    if (ad_ws_reg_key_exists(np)) return 1;

    // Legacy WinPcap: "...\Services\NPF"
    np[34]='N'; np[35]='P'; np[36]='F'; np[37]=0;
    if (ad_ws_reg_key_exists(np)) return 1;

    return 0;
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// 5. Process scan — enumerate running processes, match image names against
// the full Wireshark binary family (GUI + CLI + extcap helpers). Hard
// signal: fires only when something is actively running.
//
// Substrings (case-insensitive) covering every executable produced by a
// default wireshark-master build:
//   wireshark     (wireshark.exe, Wireshark.exe, wireshark-<ver>.exe)
//   tshark        (tshark.exe)
//   dumpcap       (dumpcap.exe)
//   rawshark      (rawshark.exe)
//   sharkd        (sharkd.exe — Wireshark daemon)
//   capinfos      (capinfos.exe)
//   editcap       (editcap.exe)
//   mergecap      (mergecap.exe)
//   text2pcap     (text2pcap.exe)
//   sshdump       (sshdump.exe, extcap)
//   etwdump       (etwdump.exe, extcap)
//   androiddump   (androiddump.exe, extcap)
//   udpdump       (udpdump.exe, extcap)
//   randpktdump   (randpktdump.exe, extcap)
//   dpauxmon      (dpauxmon.exe, extcap)
//   ciscodump     (ciscodump.exe, extcap)
// ---------------------------------------------------------------------------
#ifndef AD_WS_PROC_INFO_DEFINED
#define AD_WS_PROC_INFO_DEFINED
typedef struct {
    u32  NextEntryOffset;
    u32  NumberOfThreads;
    u8   _timing[0x30];
    u16  ImgLen;
    u16  ImgMaxLen;
    u32  _pad;
    u16* ImgBuffer;
    u8   _rest[8];
    void* UniqueProcessId;
} AD_WS_PROC_INFO;
#endif

ANTIDEBUG_INLINE b32 ad_ws_image_is_wireshark_family(const u16* img, u32 n_chars) {
    static const u16 n_wireshark   [] = {'w','i','r','e','s','h','a','r','k'};
    static const u16 n_tshark      [] = {'t','s','h','a','r','k'};
    static const u16 n_dumpcap     [] = {'d','u','m','p','c','a','p'};
    static const u16 n_rawshark    [] = {'r','a','w','s','h','a','r','k'};
    static const u16 n_sharkd      [] = {'s','h','a','r','k','d'};
    static const u16 n_capinfos    [] = {'c','a','p','i','n','f','o','s'};
    static const u16 n_editcap     [] = {'e','d','i','t','c','a','p'};
    static const u16 n_mergecap    [] = {'m','e','r','g','e','c','a','p'};
    static const u16 n_text2pcap   [] = {'t','e','x','t','2','p','c','a','p'};
    static const u16 n_sshdump     [] = {'s','s','h','d','u','m','p'};
    static const u16 n_etwdump     [] = {'e','t','w','d','u','m','p'};
    static const u16 n_androiddump [] = {'a','n','d','r','o','i','d','d','u','m','p'};
    static const u16 n_udpdump     [] = {'u','d','p','d','u','m','p'};
    static const u16 n_randpktdump [] = {'r','a','n','d','p','k','t','d','u','m','p'};
    static const u16 n_dpauxmon    [] = {'d','p','a','u','x','m','o','n'};
    static const u16 n_ciscodump   [] = {'c','i','s','c','o','d','u','m','p'};

    if (ad_ws_wcontains_ci(img, n_chars, n_wireshark,    9u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_tshark,       6u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_dumpcap,      7u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_rawshark,     8u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_sharkd,       6u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_capinfos,     8u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_editcap,      7u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_mergecap,     8u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_text2pcap,    9u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_sshdump,      7u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_etwdump,      7u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_androiddump, 11u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_udpdump,      7u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_randpktdump, 11u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_dpauxmon,     8u)) return 1;
    if (ad_ws_wcontains_ci(img, n_chars, n_ciscodump,    9u)) return 1;
    return 0;
}

// Helpers: returns 1 if any process image matches the Wireshark family.
// If match_parent_pid != 0, also reports (via out_parent_match) whether the
// matched process is specifically our parent process.
ANTIDEBUG_INLINE b32 ad_ws_enumerate_processes(u32 parent_pid, b32* out_parent_match) {
    if (out_parent_match) *out_parent_match = 0;

    static u16 s_ssn_qsi   = AD_SSN_UNRESOLVED;
    static u16 s_ssn_alloc = AD_SSN_UNRESOLVED;
    static u16 s_ssn_free  = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi,   NtQuerySystemInformation, 25);
    AD_RESOLVE_SSN_ENC(s_ssn_alloc, NtAllocateVirtualMemory,  24);
    AD_RESOLVE_SSN_ENC(s_ssn_free,  NtFreeVirtualMemory,      20);
    if (s_ssn_qsi == AD_SSN_FAILED || s_ssn_alloc == AD_SSN_FAILED ||
        s_ssn_free == AD_SSN_FAILED) return 0;

    void* buf = 0;
    u64   buf_size = 0x80000ULL;
    u32   retries = 0;
    b32   ok = 0;
    ad_ntstatus_t st;

    while (retries < 4u) {
        void* tmp = 0; u64 tmp_sz = buf_size;
        st = AD_SYSCALL6(s_ssn_alloc, AD_CURRENT_PROCESS, &tmp, (u64)0,
            &tmp_sz, (u64)(0x1000UL | 0x2000UL), (u64)0x04UL);
        if (!AD_NT_SUCCESS(st)) return 0;
        buf = tmp;

        u32 needed = 0;
        st = AD_SYSCALL4(s_ssn_qsi, (u64)5, buf, (u64)buf_size, &needed);
        if (AD_NT_SUCCESS(st)) { ok = 1; break; }

        void* fb = buf; u64 fs = 0ULL;
        AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &fb, &fs, (u64)0x8000UL);
        buf = 0;

        if ((u32)st == 0xC0000004UL) {
            buf_size = (needed > 0u) ? ((u64)needed + 0x10000ULL) : (buf_size * 2ULL);
        } else break;
        retries++;
    }
    if (!ok || !buf) return 0;

    b32 found = 0;
    u32 our_pid = (u32)(u64)__readgsqword(0x40);
    u8* ptr = (u8*)buf;
    u32 guard = 0;
    while (guard < 2048u) {
        guard++;
        const AD_WS_PROC_INFO* p = (const AD_WS_PROC_INFO*)ptr;
        u32 n_chars = (u32)(p->ImgLen / 2u);
        const u16* img = p->ImgBuffer;
        u32 pid = (u32)(u64)p->UniqueProcessId;
        if (img && n_chars > 0u && pid != our_pid && pid != 0u && pid != 4u) {
            if (ad_ws_image_is_wireshark_family(img, n_chars)) {
                found = 1;
                if (parent_pid != 0u && pid == parent_pid && out_parent_match)
                    *out_parent_match = 1;
                // do not early-break; parent match check may still be pending
            }
        }
        if (p->NextEntryOffset == 0u) break;
        ptr += p->NextEntryOffset;
    }

    { void* fb = buf; u64 fs = 0ULL;
      AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &fb, &fs, (u64)0x8000UL); }

    return found;
}

ANTIDEBUG_INLINE b32 ad_ws_process_running(void) {
    b32 dummy;
    return ad_ws_enumerate_processes(0u, &dummy);
}

// ---------------------------------------------------------------------------
// 6. Parent-process check — extcap tools are spawned by Wireshark as child
// processes communicating via stdio/pipes. If our parent is a Wireshark
// binary, we were launched by Wireshark.
//
// Reads our parent PID from PEB->ProcessParameters->InheritedFromUniqueProcessId
// (PEB.ProcessParameters at 0x20, then the PBI variant via
// NtQueryInformationProcess class 0 gives a reliable InheritedFrom). We use
// the cheaper NtQIP path.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// 7. Foreground window check — a freshly launched app typically takes the
// foreground. GetForegroundWindow() + title substring match.
// ---------------------------------------------------------------------------
typedef void* (__stdcall *FN_GetForegroundWindow)(void);

ANTIDEBUG_INLINE b32 ad_ws_foreground_is_wireshark(void) {
    FN_GetForegroundWindow pFg = (FN_GetForegroundWindow)
        ad_resolve_api(AD_HASH_USER32, AD_HASH("GetForegroundWindow"));
    if (!pFg) return 0;
    FN_GetWindowTextW pGet = (FN_GetWindowTextW)
        ad_resolve_api(AD_HASH_USER32, AD_HASH("GetWindowTextW"));
    if (!pGet) return 0;

    void* hwnd = pFg();
    if (!hwnd) return 0;

    static const u16 w_needle[] = {'W','i','r','e','s','h','a','r','k'};
    u16 buf[256];
    int len = pGet(hwnd, buf, 255);
    if (len <= 0 || (u32)len >= 256u) return 0;
    return ad_ws_wcontains_ci(buf, (u32)len, w_needle, 9u);
}

// ---------------------------------------------------------------------------
// 8. Recent-launch check — scan processes, compare CreateTime against the
// current system clock (KUSER_SHARED_DATA.SystemTime). If any Wireshark
// binary was created within AD_WS_RECENT_WINDOW_100NS ago → launching now.
//
// FILETIME layout on NT: 64-bit count of 100 ns intervals since 1601-01-01.
// KUSER_SHARED_DATA.SystemTime (offset 0x14) is a KSYSTEM_TIME tri-DWORD
// tear-protected read (Low, High1, High2). Retry until High1 == High2.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u64 ad_ws_system_time_100ns(void) {
    volatile u32* kusd = (volatile u32*)0x7FFE0014ULL;  // SystemTime.Low
    u32 low, high1, high2;
    do {
        high2 = kusd[2];
        low   = kusd[0];
        high1 = kusd[1];
    } while (high1 != high2);
    return ((u64)high1 << 32) | (u64)low;
}

ANTIDEBUG_INLINE b32 ad_ws_recent_launch(void) {
    static u16 s_ssn_qsi   = AD_SSN_UNRESOLVED;
    static u16 s_ssn_alloc = AD_SSN_UNRESOLVED;
    static u16 s_ssn_free  = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qsi,   NtQuerySystemInformation, 25);
    AD_RESOLVE_SSN_ENC(s_ssn_alloc, NtAllocateVirtualMemory,  24);
    AD_RESOLVE_SSN_ENC(s_ssn_free,  NtFreeVirtualMemory,      20);
    if (s_ssn_qsi == AD_SSN_FAILED || s_ssn_alloc == AD_SSN_FAILED ||
        s_ssn_free == AD_SSN_FAILED) return 0;

    u64 now = ad_ws_system_time_100ns();

    void* buf = 0;
    u64   buf_size = 0x80000ULL;
    u32   retries = 0;
    b32   ok = 0;
    ad_ntstatus_t st;

    while (retries < 4u) {
        void* tmp = 0; u64 tmp_sz = buf_size;
        st = AD_SYSCALL6(s_ssn_alloc, AD_CURRENT_PROCESS, &tmp, (u64)0,
            &tmp_sz, (u64)(0x1000UL | 0x2000UL), (u64)0x04UL);
        if (!AD_NT_SUCCESS(st)) return 0;
        buf = tmp;

        u32 needed = 0;
        st = AD_SYSCALL4(s_ssn_qsi, (u64)5, buf, (u64)buf_size, &needed);
        if (AD_NT_SUCCESS(st)) { ok = 1; break; }

        void* fb = buf; u64 fs = 0ULL;
        AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &fb, &fs, (u64)0x8000UL);
        buf = 0;
        if ((u32)st == 0xC0000004UL) {
            buf_size = (needed > 0u) ? ((u64)needed + 0x10000ULL) : (buf_size * 2ULL);
        } else break;
        retries++;
    }
    if (!ok || !buf) return 0;

    b32 hit = 0;
    u32 our_pid = (u32)(u64)__readgsqword(0x40);
    u8* ptr = (u8*)buf;
    u32 guard = 0;
    while (guard < 2048u) {
        guard++;
        const AD_WS_PROC_INFO* p = (const AD_WS_PROC_INFO*)ptr;
        u32 n_chars = (u32)(p->ImgLen / 2u);
        const u16* img = p->ImgBuffer;
        u32 pid = (u32)(u64)p->UniqueProcessId;

        if (img && n_chars > 0u && pid != our_pid && pid != 0u && pid != 4u) {
            if (ad_ws_image_is_wireshark_family(img, n_chars)) {
                // CreateTime is at offset 0x20 of SYSTEM_PROCESS_INFORMATION.
                u64 create_time = *(const u64*)((const u8*)p + 0x20);
                if (create_time != 0ULL && now >= create_time) {
                    u64 age_100ns = now - create_time;
                    if (age_100ns <= AD_WS_RECENT_WINDOW_100NS) {
                        hit = 1;
                        break;
                    }
                }
            }
        }
        if (p->NextEntryOffset == 0u) break;
        ptr += p->NextEntryOffset;
    }

    { void* fb = buf; u64 fs = 0ULL;
      AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &fb, &fs, (u64)0x8000UL); }

    return hit;
}

ANTIDEBUG_INLINE b32 ad_ws_parent_is_wireshark(void) {
    static u16 s_ssn_qip = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn_qip, NtQueryInformationProcess, 26);
    if (s_ssn_qip == AD_SSN_FAILED) return 0;

    AD_PROCESS_BASIC_INFO pbi; AD_ZERO_BUF(&pbi, sizeof(pbi));
    u32 rl = 0;
    ad_ntstatus_t st = AD_SYSCALL5(s_ssn_qip,
        AD_CURRENT_PROCESS, (u64)0,  // ProcessBasicInformation = 0
        &pbi, (u64)sizeof(pbi), &rl);
    if (!AD_NT_SUCCESS(st)) return 0;

    u32 parent_pid = (u32)(u64)pbi.InheritedFromUniqueProcessId;
    if (parent_pid == 0u) return 0;

    b32 parent_match = 0;
    ad_ws_enumerate_processes(parent_pid, &parent_match);
    return parent_match;
}

// ---------------------------------------------------------------------------
// 9. Real-time launch hook via SetWinEventHook(EVENT_SYSTEM_FOREGROUND).
//
// Spins a dedicated worker thread with a message pump. The thread installs
// an accessibility event hook that fires every time the foreground window
// changes system-wide. On fire, the callback reads the new window's title
// and sets a sticky atomic flag if it contains "Wireshark".
//
// This is a REAL in-process hook (not polling). The OS calls our callback
// directly from user32's event dispatcher the moment Wireshark takes focus,
// which happens within a few tens of milliseconds of the main window being
// shown. Install once at program init, then query ad_ws_hook_triggered()
// cheaply from anywhere.
//
// The callback runs on the worker thread (WINEVENT_OUTOFCONTEXT), so the
// thread MUST be pumping messages for the hook to fire — hence the
// GetMessageW loop below.
// ---------------------------------------------------------------------------

typedef void* AD_HWINEVENTHOOK;
typedef void  (__stdcall *AD_WINEVENTPROC)(AD_HWINEVENTHOOK, u32, void*, long, long, u32, u32);
typedef AD_HWINEVENTHOOK (__stdcall *FN_SetWinEventHook)(
    u32 eventMin, u32 eventMax, void* hmodWinEventProc,
    AD_WINEVENTPROC pfn, u32 idProcess, u32 idThread, u32 dwFlags);
typedef int (__stdcall *FN_UnhookWinEvent)(AD_HWINEVENTHOOK);

typedef struct {
    void* hwnd;
    u32   message;
    u64   wParam;
    u64   lParam;
    u32   time;
    s32   pt_x;
    s32   pt_y;
    u32   _pad;
} AD_WS_MSG;

typedef int  (__stdcall *FN_GetMessageW)(AD_WS_MSG*, void*, u32, u32);
typedef int  (__stdcall *FN_DispatchMessageW)(const AD_WS_MSG*);
typedef void* (__stdcall *FN_CreateThread)(void*, u64, void*, void*, u32, u32*);

// Global flags (sticky). Extern visibility allowed across TUs that include
// this header — each TU gets its own static copy; the MAIN TU that installs
// the hook is the authoritative one.
static volatile b32 g_ad_ws_hook_fired   = 0;
static volatile b32 g_ad_ws_hook_stop    = 0;
static volatile b32 g_ad_ws_hook_running = 0;

// WINEVENT callback — runs on the worker thread.
static void __stdcall ad_ws_winevent_cb(
    AD_HWINEVENTHOOK hook, u32 event, void* hwnd,
    long idObject, long idChild, u32 tid, u32 evTime)
{
    (void)hook; (void)event; (void)tid; (void)evTime;
    if (!hwnd) return;
    if (idObject != 0 || idChild != 0) return;   // top-level window only

    FN_GetWindowTextW pGet = (FN_GetWindowTextW)
        ad_resolve_api(AD_HASH_USER32, AD_HASH("GetWindowTextW"));
    if (!pGet) return;

    u16 buf[256];
    int len = pGet(hwnd, buf, 255);
    if (len <= 0 || (u32)len >= 256u) return;

    static const u16 n_ws[] = {'W','i','r','e','s','h','a','r','k'};
    if (ad_ws_wcontains_ci(buf, (u32)len, n_ws, 9u)) {
        g_ad_ws_hook_fired = 1;
    }
}

// Worker thread: install hook + pump messages until stop flag set.
static unsigned long __stdcall ad_ws_hook_worker(void* param) {
    (void)param;

    FN_SetWinEventHook pSet = (FN_SetWinEventHook)
        ad_resolve_api(AD_HASH_USER32, AD_HASH("SetWinEventHook"));
    FN_UnhookWinEvent pUnhook = (FN_UnhookWinEvent)
        ad_resolve_api(AD_HASH_USER32, AD_HASH("UnhookWinEvent"));
    FN_GetMessageW pGetMsg = (FN_GetMessageW)
        ad_resolve_api(AD_HASH_USER32, AD_HASH("GetMessageW"));
    FN_DispatchMessageW pDisp = (FN_DispatchMessageW)
        ad_resolve_api(AD_HASH_USER32, AD_HASH("DispatchMessageW"));

    if (!pSet || !pUnhook || !pGetMsg || !pDisp) return 1;

    // EVENT_SYSTEM_FOREGROUND = 0x0003
    // WINEVENT_OUTOFCONTEXT   = 0x0000
    // WINEVENT_SKIPOWNPROCESS = 0x0002
    AD_HWINEVENTHOOK hook = pSet(
        0x0003u, 0x0003u,
        (void*)0, ad_ws_winevent_cb,
        0u, 0u, 0x0002u);
    if (!hook) { g_ad_ws_hook_running = 0; return 1; }

    g_ad_ws_hook_running = 1;

    AD_WS_MSG msg;
    while (!g_ad_ws_hook_stop) {
        int r = pGetMsg(&msg, (void*)0, 0u, 0u);
        if (r == 0 || r < 0) break;       // WM_QUIT or error
        pDisp(&msg);
    }

    pUnhook(hook);
    g_ad_ws_hook_running = 0;
    return 0;
}

// Install the hook worker. Returns 1 if thread spawned.
ANTIDEBUG_INLINE b32 ad_ws_hook_install(void) {
    if (g_ad_ws_hook_running) return 1;       // already armed

    FN_CreateThread pCT = (FN_CreateThread)
        ad_resolve_api(AD_HASH_KERNEL32, AD_HASH("CreateThread"));
    if (!pCT) return 0;

    u32 tid = 0;
    void* th = pCT((void*)0, 0ULL,
                   (void*)ad_ws_hook_worker, (void*)0, 0u, &tid);
    return (b32)(th != (void*)0);
}

// Cheap query — just reads the sticky flag.
ANTIDEBUG_INLINE b32 ad_ws_hook_triggered(void) {
    return (b32)(g_ad_ws_hook_fired != 0);
}

// Aggregate check — returns bitmask of vectors that fired.
//
// The Npcap/NPF service vector (AD_WS_NPCAP_SVC) is deliberately EXCLUDED
// from this aggregate: the driver service can be registered long-term even
// when no capture tool is actively running, which would produce a false
// positive on machines where the user installed Npcap for an unrelated
// reason (Nmap, another packet analyzer, Zeek, etc.). The function
// ad_ws_npcap_driver_installed() remains available for callers who want
// to opt in to that signal explicitly.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_wireshark_detect(void) {
    u32 mask = 0u;
    if (ad_ws_module_loaded())           mask |= AD_WS_MODULE;
    if (ad_ws_window_present())          mask |= AD_WS_WINDOW;
    if (ad_ws_wireshark_installed())     mask |= AD_WS_REGKEY;
    if (ad_ws_process_running())         mask |= AD_WS_PROCESS;
    if (ad_ws_parent_is_wireshark())     mask |= AD_WS_PARENT;
    if (ad_ws_foreground_is_wireshark()) mask |= AD_WS_FOREGROUND;
    if (ad_ws_recent_launch())           mask |= AD_WS_RECENT;
    if (ad_ws_hook_triggered())          mask |= AD_WS_HOOK_EVENT;
    return mask;
}

// Composite weighted score — tuned so "just launched" signals dominate.
//   parent      : 20 (spawned by Wireshark — near-certain)
//   recent      : 16 (process created < N seconds ago — launching NOW)
//   foreground  : 12 (Wireshark just took focus)
//   process     : 14 (running — stronger baseline)
//   window      : 10 (GUI open)
//   module      :  8 (packet stack in us)
//   regkey      :  4 (installed)
ANTIDEBUG_INLINE u32 ad_wireshark_score(void) {
    u32 m = ad_wireshark_detect();
    u32 s = 0;
    if (m & AD_WS_PARENT)     s += 20u;
    if (m & AD_WS_RECENT)     s += 16u;
    if (m & AD_WS_FOREGROUND) s += 12u;
    if (m & AD_WS_PROCESS)    s += 14u;
    if (m & AD_WS_WINDOW)     s += 10u;
    if (m & AD_WS_MODULE)     s +=  8u;
    if (m & AD_WS_REGKEY)     s +=  4u;
    if (m & AD_WS_HOOK_EVENT) s += 18u;  // real-time hook fired
    return s;
}

#else  // !_MSC_VER
ANTIDEBUG_INLINE u32 ad_wireshark_detect(void) { return 0u; }
ANTIDEBUG_INLINE u32 ad_wireshark_score(void)  { return 0u; }
#endif // _MSC_VER

#endif // ANTIDEBUG_WIRESHARK_DETECT_H
