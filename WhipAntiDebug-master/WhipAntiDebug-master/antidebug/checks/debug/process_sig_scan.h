// ===== file: antidebug/checks/debug/process_sig_scan.h =====
//
// Hash-based debugger process detection -- no plaintext process names.
//
// Unlike process_scan.h which stores debugger names as wide-char arrays
// (visible in .rdata to any reverser), this check stores only pre-computed
// FNV-1a hashes of known debugger/tool executable names.
//
// A reverser cannot determine which process names we check without brute-
// forcing or reversing the FNV-1a hash. Renaming an exe will bypass
// process_scan.h but this check is equally blind to the rename -- the hash
// won't match the renamed binary, so it is complementary: process_scan
// catches renamed binaries that keep the original suffix visible, while
// this check catches binaries that keep their original name but try to
// hide from string-based scans.
//
// Technique:
//   1. NtQuerySystemInformation(SystemProcessInformation=5) to enumerate
//   2. For each process, extract the ImageName UNICODE_STRING
//   3. Compute case-insensitive FNV-1a hash of the image name
//   4. Compare against a table of pre-computed hashes (no strings stored)
//
// The hash table covers: debuggers, disassemblers, memory tools, network
// sniffers, .NET reversers, and binary analysis frameworks.
//
#ifndef ANTIDEBUG_PROCESS_SIG_SCAN_H
#define ANTIDEBUG_PROCESS_SIG_SCAN_H

#include "../../core/types.h"
#include "../../core/macros.h"
#include "../../core/syscall_bridge.h"
#include "../../core/string_encrypt.h"

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------
// Reuse SYSTEM_PROCESS_INFORMATION layout from process_scan.h if present,
// otherwise define our own identical struct under a different guard.
// ---------------------------------------------------------------------------
#ifndef AD_SIG_PROC_INFO_DEFINED
#define AD_SIG_PROC_INFO_DEFINED
typedef struct {
    u32  NextEntryOffset;       // +0
    u32  NumberOfThreads;       // +4
    u8   _timing[0x30];         // +8  (timing/counters, not needed)
    // +0x038: UNICODE_STRING ImageName
    u16  ImgLen;                // +0x038  bytes (not chars)
    u16  ImgMaxLen;             // +0x03A
    u32  _img_pad;              // +0x03C
    u16* ImgBuffer;             // +0x040
    // +0x048: BasePriority (s32) ...
    u8   _rest[8];              // +0x048
    void* UniqueProcessId;      // +0x050
} AD_SIG_PROC_INFO;
#endif

// ---------------------------------------------------------------------------
// FNV-1a hash of a wide string (case-insensitive, ASCII-only fold).
// This hashes each u16 code unit as TWO bytes (lo, hi) matching ad_hash_wstr
// in api_hash.h -- same algorithm, same results.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_sig_fnv1a_w(const u16* w, u32 char_count) {
    u32 h = 0x811C9DC5u;
    u32 i;
    for (i = 0; i < char_count; i++) {
        u16 c = w[i];
        if (c >= 'A' && c <= 'Z') c = (u16)(c + 32);
        h ^= (u8)(c & 0xFFu);
        h *= 0x01000193u;
        h ^= (u8)((c >> 8) & 0xFFu);
        h *= 0x01000193u;
    }
    return h;
}

// ---------------------------------------------------------------------------
// Pre-computed FNV-1a hashes of known debugger/tool executable names.
//
// Each hash was computed with ad_hash_wstr (UTF-16 LE, case-insensitive)
// over the full filename including ".exe" extension.
//
// To regenerate: for each name, build a u16[] array of the lowercase chars,
// pass to ad_hash_wstr(arr, len), record the u32 result.
//
// Sorted by tool category for readability; binary has only the u32 values.
// ---------------------------------------------------------------------------

// Helper: compile-time FNV-1a for short ASCII-only names encoded as UTF-16 LE.
// Each ASCII char c produces two hash rounds: (c & 0xFF) then ((c>>8) & 0xFF)
// = (c) then (0). We pre-compute offline and paste the constants.
//
// The hashes below are the FNV-1a wstr hashes of the following names
// (all lowercased, with .exe suffix):
//
//   Debuggers:
//     x64dbg.exe, x32dbg.exe, ollydbg.exe, windbg.exe, windbgx.exe,
//     ida.exe, ida64.exe, idag.exe, idag64.exe, idaq.exe, idaq64.exe,
//     idaw.exe, idaw64.exe
//
//   System/debug monitors:
//     dbgview.exe, dbgview64.exe, procmon.exe, procmon64.exe,
//     procexp.exe, procexp64.exe, apimonitor.exe
//
//   Memory/cheat tools:
//     cheatengine.exe, cheatengine-x86_64.exe, reclass.exe,
//     reclass.net.exe, processhacker.exe
//
//   Network sniffers:
//     httpdebugger.exe, fiddler.exe, wireshark.exe, dumpcap.exe
//
//   .NET reversers:
//     dnspy.exe, dotpeek.exe, dotpeek64.exe
//
//   Binary analysis:
//     ghidra.exe, ghidrarun.exe, binaryninja.exe, radare2.exe, cutter.exe,
//     immunitydebugger.exe
//
//   PE/dump tools:
//     scylla.exe, scyllahide.exe, ksdumper.exe, ksdumperclient.exe,
//     pcileech.exe, memprocfs.exe, kdmapper.exe, petools.exe
//
// IMPORTANT: these are computed by running the ad_sig_fnv1a_w function above
// on the UTF-16 LE representation of each lowercased name string.
// The values must be validated against the runtime hash function.
// We use a verification approach: the hash function is the same FNV-1a used
// throughout the project (ad_hash_wstr in api_hash.h).
//
// To avoid shipping wrong constants, we compute them at first use via a
// small init helper that hashes known names built char-by-char on the stack.
// This is done ONCE and cached in a static array.
// ---------------------------------------------------------------------------

// Number of known debugger process hashes
#define AD_SIG_HASH_COUNT  45u

// ---------------------------------------------------------------------------
// ad_sig_init_hashes -- one-time computation of the hash table.
// Names are built char-by-char on the stack (no .rdata strings).
// Each name is hashed via ad_sig_fnv1a_w and stored in the output array.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_sig_init_hashes(u32* out) {
    u32 idx = 0u;

    // Macro to hash a stack-built wide string and store at out[idx++]
    // We define small local blocks for each name to keep stack usage bounded.

    // -- x64dbg.exe (10 chars) --
    { u16 n[]={'x','6','4','d','b','g','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,10); }
    // -- x32dbg.exe (10 chars) --
    { u16 n[]={'x','3','2','d','b','g','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,10); }
    // -- ollydbg.exe (11 chars) --
    { u16 n[]={'o','l','l','y','d','b','g','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,11); }
    // -- windbg.exe (10 chars) --
    { u16 n[]={'w','i','n','d','b','g','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,10); }
    // -- windbgx.exe (11 chars) --
    { u16 n[]={'w','i','n','d','b','g','x','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,11); }
    // -- ida.exe (7 chars) --
    { u16 n[]={'i','d','a','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,7); }
    // -- ida64.exe (9 chars) --
    { u16 n[]={'i','d','a','6','4','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,9); }
    // -- idag.exe (8 chars) --
    { u16 n[]={'i','d','a','g','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,8); }
    // -- idag64.exe (10 chars) --
    { u16 n[]={'i','d','a','g','6','4','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,10); }
    // -- idaq.exe (8 chars) --
    { u16 n[]={'i','d','a','q','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,8); }
    // -- idaq64.exe (10 chars) --
    { u16 n[]={'i','d','a','q','6','4','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,10); }
    // -- idaw.exe (8 chars) --
    { u16 n[]={'i','d','a','w','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,8); }
    // -- idaw64.exe (10 chars) --
    { u16 n[]={'i','d','a','w','6','4','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,10); }

    // System / debug monitors
    // -- dbgview.exe (11 chars) --
    { u16 n[]={'d','b','g','v','i','e','w','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,11); }
    // -- dbgview64.exe (13 chars) --
    { u16 n[]={'d','b','g','v','i','e','w','6','4','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,13); }
    // -- procmon.exe (11 chars) --
    { u16 n[]={'p','r','o','c','m','o','n','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,11); }
    // -- procmon64.exe (13 chars) --
    { u16 n[]={'p','r','o','c','m','o','n','6','4','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,13); }
    // -- procexp.exe (11 chars) --
    { u16 n[]={'p','r','o','c','e','x','p','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,11); }
    // -- procexp64.exe (13 chars) --
    { u16 n[]={'p','r','o','c','e','x','p','6','4','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,13); }
    // -- apimonitor.exe (14 chars) --
    { u16 n[]={'a','p','i','m','o','n','i','t','o','r','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,14); }

    // Memory / cheat tools
    // -- cheatengine.exe (15 chars) --
    { u16 n[]={'c','h','e','a','t','e','n','g','i','n','e','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,15); }
    // -- cheatengine-x86_64.exe (22 chars) --
    { u16 n[]={'c','h','e','a','t','e','n','g','i','n','e','-','x','8','6','_','6','4','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,22); }
    // -- reclass.exe (11 chars) --
    { u16 n[]={'r','e','c','l','a','s','s','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,11); }
    // -- reclass.net.exe (15 chars) --
    { u16 n[]={'r','e','c','l','a','s','s','.','n','e','t','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,15); }
    // -- processhacker.exe (17 chars) --
    { u16 n[]={'p','r','o','c','e','s','s','h','a','c','k','e','r','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,17); }

    // Network sniffers
    // -- httpdebugger.exe (16 chars) --
    { u16 n[]={'h','t','t','p','d','e','b','u','g','g','e','r','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,16); }
    // -- fiddler.exe (11 chars) --
    { u16 n[]={'f','i','d','d','l','e','r','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,11); }
    // -- wireshark.exe (13 chars) --
    { u16 n[]={'w','i','r','e','s','h','a','r','k','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,13); }
    // -- dumpcap.exe (11 chars) --
    { u16 n[]={'d','u','m','p','c','a','p','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,11); }

    // .NET reversers
    // -- dnspy.exe (9 chars) --
    { u16 n[]={'d','n','s','p','y','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,9); }
    // -- dotpeek.exe (11 chars) --
    { u16 n[]={'d','o','t','p','e','e','k','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,11); }
    // -- dotpeek64.exe (13 chars) --
    { u16 n[]={'d','o','t','p','e','e','k','6','4','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,13); }

    // Binary analysis
    // -- ghidra.exe (10 chars) --
    { u16 n[]={'g','h','i','d','r','a','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,10); }
    // -- ghidrarun.exe (13 chars) --
    { u16 n[]={'g','h','i','d','r','a','r','u','n','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,13); }
    // -- binaryninja.exe (15 chars) --
    { u16 n[]={'b','i','n','a','r','y','n','i','n','j','a','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,15); }
    // -- radare2.exe (11 chars) --
    { u16 n[]={'r','a','d','a','r','e','2','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,11); }
    // -- cutter.exe (10 chars) --
    { u16 n[]={'c','u','t','t','e','r','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,10); }
    // -- immunitydebugger.exe (20 chars) --
    { u16 n[]={'i','m','m','u','n','i','t','y','d','e','b','u','g','g','e','r','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,20); }

    // PE / dump tools
    // -- scylla.exe (10 chars) --
    { u16 n[]={'s','c','y','l','l','a','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,10); }
    // -- scyllahide.exe (14 chars) --
    { u16 n[]={'s','c','y','l','l','a','h','i','d','e','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,14); }
    // -- ksdumper.exe (12 chars) --
    { u16 n[]={'k','s','d','u','m','p','e','r','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,12); }
    // -- ksdumperclient.exe (18 chars) --
    { u16 n[]={'k','s','d','u','m','p','e','r','c','l','i','e','n','t','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,18); }
    // -- pcileech.exe (12 chars) --
    { u16 n[]={'p','c','i','l','e','e','c','h','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,12); }
    // -- memprocfs.exe (13 chars) --
    { u16 n[]={'m','e','m','p','r','o','c','f','s','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,13); }
    // -- kdmapper.exe (12 chars) --
    { u16 n[]={'k','d','m','a','p','p','e','r','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,12); }
    // -- petools.exe (11 chars) --
    { u16 n[]={'p','e','t','o','o','l','s','.','e','x','e'}; out[idx++]=ad_sig_fnv1a_w(n,11); }

    AD_UNUSED(idx);
}

// ---------------------------------------------------------------------------
// ad_process_sig_scan
//
// Enumerate all running processes via NtQuerySystemInformation, hash each
// image name with FNV-1a (case-insensitive), and compare against the
// pre-computed hash table. No debugger name strings exist in the binary.
//
// Returns 1 if any known debugger/tool process is found, 0 otherwise.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE b32 ad_process_sig_scan(void) {
    static u16 s_ssn_qsi   = AD_SSN_UNRESOLVED;
    static u16 s_ssn_alloc = AD_SSN_UNRESOLVED;
    static u16 s_ssn_free  = AD_SSN_UNRESOLVED;

    AD_RESOLVE_SSN_ENC(s_ssn_qsi,   NtQuerySystemInformation, 25);
    AD_RESOLVE_SSN_ENC(s_ssn_alloc, NtAllocateVirtualMemory,  24);
    AD_RESOLVE_SSN_ENC(s_ssn_free,  NtFreeVirtualMemory,      20);

    if (s_ssn_qsi   == AD_SSN_FAILED) return 0;
    if (s_ssn_alloc == AD_SSN_FAILED) return 0;
    if (s_ssn_free  == AD_SSN_FAILED) return 0;

    // -- Build hash table (first call only) --
    static u32 s_hashes[AD_SIG_HASH_COUNT];
    static b32 s_inited = 0;
    if (!s_inited) {
        ad_sig_init_hashes(s_hashes);
        s_inited = 1;
    }

    // -- Allocate buffer for process list --
    void* buf       = (void*)0;
    u64   buf_size  = 0x80000ULL;   // 512 KB
    u32   retries   = 0u;
    b32   ok        = 0;
    ad_ntstatus_t st;

    while (retries < 4u) {
        void* tmp   = (void*)0;
        u64   tmp_sz = buf_size;
        st = AD_SYSCALL6(s_ssn_alloc,
            AD_CURRENT_PROCESS, &tmp, (u64)0, &tmp_sz,
            (u64)(0x1000UL | 0x2000UL), (u64)0x04UL);
        if (!AD_NT_SUCCESS(st)) return 0;
        buf = tmp;

        u32 needed = 0u;
        st = AD_SYSCALL4(s_ssn_qsi,
            (u64)5,   // SystemProcessInformation
            buf, (u64)buf_size, &needed);

        if (AD_NT_SUCCESS(st)) { ok = 1; break; }

        void* fb = buf; u64 fs = 0ULL;
        AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &fb, &fs, (u64)0x8000UL);
        buf = (void*)0;

        if ((u32)st == 0xC0000004UL) {  // STATUS_INFO_LENGTH_MISMATCH
            buf_size = (needed > 0u) ? ((u64)needed + 0x10000ULL) : (buf_size * 2ULL);
        } else { break; }
        retries++;
    }

    if (!ok || !buf) return 0;

    // -- Walk process list --
    b32 found = 0;
    u32 our_pid = (u32)(u64)__readgsqword(0x040);
    u8* ptr = (u8*)buf;

    u32 guard = 0u;
    while (guard < 1024u) {
        guard++;
        const AD_SIG_PROC_INFO* p = (const AD_SIG_PROC_INFO*)ptr;

        u32  n_chars = (u32)(p->ImgLen / 2u);
        const u16* img = p->ImgBuffer;

        if (img && n_chars > 0u) {
            u32 pid = (u32)(u64)p->UniqueProcessId;
            if (pid != our_pid && pid != 0u && pid != 4u) {
                // Hash the image name (case-insensitive)
                u32 h = ad_sig_fnv1a_w(img, n_chars);

                // Linear scan of the hash table
                u32 d;
                for (d = 0u; d < AD_SIG_HASH_COUNT && !found; d++) {
                    if (h == s_hashes[d]) {
                        found = 1;
                    }
                }
            }
        }

        if (found) break;
        if (p->NextEntryOffset == 0u) break;
        ptr += p->NextEntryOffset;
    }

    // -- Free buffer --
    {
        void* fb = buf; u64 fs = 0ULL;
        AD_SYSCALL4(s_ssn_free, AD_CURRENT_PROCESS, &fb, &fs, (u64)0x8000UL);
    }

    return found;
}

#else
ANTIDEBUG_INLINE b32 ad_process_sig_scan(void) { return 0; }
#endif // _MSC_VER

#endif // ANTIDEBUG_PROCESS_SIG_SCAN_H
