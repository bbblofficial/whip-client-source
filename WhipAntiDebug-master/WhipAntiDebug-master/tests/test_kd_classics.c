// ===== file: tests/test_kd_classics.c =====
//
// Unit harness for the kd_deep + al-khaser-classics checks. Calls each
// detection function in isolation, prints its return value, no scoring,
// no orchestrator, no flag — just raw signal values. Suitable for
// running both clean and under cdb / WinDbg to verify each check fires
// (or doesn't) appropriately.
//
// Build via the existing test target pattern. Run:
//   cmake-build-release\TestKdClassics.exe                 # clean baseline
//   cdbX64.exe -o cmake-build-release\TestKdClassics.exe   # under user-mode dbg
//

#include "antidebug/core/types.h"
#include "antidebug/core/macros.h"
#include "antidebug/core/syscall_bridge.h"
#include "antidebug/core/string_encrypt.h"
#include "antidebug/core/strenc_extra.h"
#include "antidebug/core/api_hash.h"
#include "antidebug/checks/debug/kd_deep.h"
#include "antidebug/checks/debug/al_khaser_classics.h"
#include "antidebug/checks/debug/kd_extra.h"

// ── Output via direct syscall (no CRT) ──────────────────────────────
#define AD_STRENC_NtWriteFile(buf)                                          \
    do {                                                                    \
        const u8 _k = AD_STR_KEY(0x33);                                    \
        char buf##_e[12];                                                   \
        AD_ENC(buf##_e,  0, 'N', _k); AD_ENC(buf##_e,  1, 't', _k);      \
        AD_ENC(buf##_e,  2, 'W', _k); AD_ENC(buf##_e,  3, 'r', _k);      \
        AD_ENC(buf##_e,  4, 'i', _k); AD_ENC(buf##_e,  5, 't', _k);      \
        AD_ENC(buf##_e,  6, 'e', _k); AD_ENC(buf##_e,  7, 'F', _k);      \
        AD_ENC(buf##_e,  8, 'i', _k); AD_ENC(buf##_e,  9, 'l', _k);      \
        AD_ENC(buf##_e, 10, 'e', _k);                                      \
        AD_DECODE_BUF(buf##_e, 11, _k);                                    \
        for (unsigned _ci = 0; _ci < 12; _ci++) (buf)[_ci] = buf##_e[_ci]; \
    } while (0)

typedef struct {
    union { ad_ntstatus_t Status; void* Pointer; } u;
    u64 Information;
} AD_IOSB;

static void* get_stdout(void) {
    u8* peb = (u8*)__readgsqword(0x60);
    u8* params = *(u8**)(peb + 0x20);
    return *(void**)(params + 0x28);
}

// Output goes to BOTH stdout AND a sidecar file the host can read after
// the binary exits. Useful when the binary is launched under a debugger
// that intercepts the console (cdb / x64dbg).
__declspec(dllimport) void* __stdcall CreateFileA(
    const char* fname, u32 access, u32 share, void* sd,
    u32 dispo, u32 flags, void* tpl);
__declspec(dllimport) int __stdcall WriteFile(
    void* h, const void* buf, u32 len, u32* written, void* ovl);
__declspec(dllimport) int __stdcall CloseHandle(void* h);

static void* g_log = (void*)0;

static void log_open(void) {
    if (g_log) return;
    // GENERIC_WRITE = 0x40000000, FILE_SHARE_READ = 1, CREATE_ALWAYS = 2
    g_log = CreateFileA(
        "C:\\Users\\Java\\CLionProjects\\WhipAntiDebugger\\cmake-build-release\\test_kd_run.log",
        0x40000000u, 1u, (void*)0, 2u, 0x80u, (void*)0);
    if ((u64)g_log == 0xFFFFFFFFFFFFFFFFULL) g_log = (void*)0;
}

static void write_console(const char* msg, u32 len) {
    static u16 s_ssn = AD_SSN_UNRESOLVED;
    AD_RESOLVE_SSN_ENC(s_ssn, NtWriteFile, 12);
    if (s_ssn != AD_SSN_FAILED) {
        void* h = get_stdout();
        if (h) {
            AD_IOSB iosb;
            AD_ZERO_BUF(&iosb, sizeof(iosb));
            SyscallStub(s_ssn, h, (void*)0, (void*)0, (void*)0,
                        &iosb, (void*)msg, (void*)(u64)len,
                        (void*)0, (void*)0, (void*)0, (void*)0);
        }
    }
    // Sidecar file for debugger-attached runs.
    if (!g_log) log_open();
    if (g_log) {
        u32 written = 0;
        WriteFile(g_log, msg, len, &written, (void*)0);
    }
}

static u32 strln(const char* s) { u32 n = 0; while (s[n]) n++; return n; }
static void p(const char* s) { write_console(s, strln(s)); }

static void p_check(const char* name, b32 result) {
    p("  ");
    p(name);
    p(" = ");
    p(result ? "1 (DETECTED)\r\n" : "0 (clean)\r\n");
}

int main(void) {
    if (!whip_bridge_init()) {
        p("[FATAL] whip_bridge_init failed\r\n");
        return 1;
    }

    // 2s wait gives an external `cdb -p <PID>` time to attach.
    {
        static u16 s_ssn = AD_SSN_UNRESOLVED;
        AD_RESOLVE_SSN_ENC(s_ssn, NtDelayExecution, 17);
        if (s_ssn != AD_SSN_FAILED) {
            s64 interval = -20000000LL;  // 2s, relative
            (void)AD_SYSCALL2(s_ssn, (u64)0, &interval);
        }
    }

    p("=== Whip kd-detection unit harness ===\r\n\r\n");

    // Sanity ground-truth: read PEB.BeingDebugged directly. If cdb is
    // attached this is 1, else 0. Lets us verify our test setup.
    {
        u8* peb = (u8*)__readgsqword(0x60);
        u8 bd = peb ? peb[2] : 0;
        u32 ngf = peb ? *(volatile u32*)(peb + 0xBC) : 0;
        char buf[64]; u32 bi = 0;
        const char* pre = "  [GROUND TRUTH] PEB.BeingDebugged=";
        while (*pre) buf[bi++] = *pre++;
        buf[bi++] = (bd ? '1' : '0');
        const char* mid = " NtGlobalFlag=0x";
        while (*mid) buf[bi++] = *mid++;
        const char hex[] = "0123456789ABCDEF";
        buf[bi++] = hex[(ngf >> 4) & 0xF];
        buf[bi++] = hex[ngf & 0xF];
        buf[bi++] = '\r'; buf[bi++] = '\n';
        write_console(buf, bi);
    }

    p("\r\nkd_deep checks:\r\n");
    p_check("ad_kd_check_sysinfo             ", ad_kd_check_sysinfo());
    p_check("ad_kd_check_debug_object        ", ad_kd_check_debug_object());
    p_check("ad_kd_check_sysdbg              ", ad_kd_check_sysdbg());
    p_check("ad_kd_check_query_debug_flags   ", ad_kd_check_query_debug_flags());
    p_check("ad_kd_check_set_debug_flags     ", ad_kd_check_set_debug_flags());
    p_check("ad_kd_check_close_invalid_handle", ad_kd_check_close_invalid_handle());
    p_check("ad_kd_check_dbgui_patches       ", ad_kd_check_dbgui_patches());
    p_check("ad_kd_check_create_debug_object ", ad_kd_check_create_debug_object());
    p_check("ad_kd_check_debug_port          ", ad_kd_check_debug_port());

    p("\r\nal-khaser classics:\r\n");
    p_check("ad_kc_int_2d                    ", ad_kc_int_2d());
    p_check("ad_kc_query_object_alltypes     ", ad_kc_query_object_alltypes());
    p_check("ad_kc_lfh_disabled              ", ad_kc_lfh_disabled());
    p_check("ad_kc_yield_latency             ", ad_kc_yield_latency());
    p_check("ad_kc_protected_handle          ", ad_kc_protected_handle());

    p("\r\nkd_extra checks:\r\n");
    p_check("ad_kx_self_debug_attempt        ", ad_kx_self_debug_attempt());
    p_check("ad_kx_veh_chain_count           ", ad_kx_veh_chain_count());
    p_check("ad_kx_break_on_termination      ", ad_kx_break_on_termination());

    p("\r\n=== done ===\r\n");
    return 0;
}
