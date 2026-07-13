// ===== file: tests/test_hw_via_exc.c =====
//
// Harness for hardware_via_exc.h. Two stages:
//   STAGE_CLEAN  : no HWBP → expect detected=0, all DR=0
//   STAGE_X64DBG : 15s pause. Attach x64dbg, set HW exec BP on any code
//                  address, resume. Expect detected=1, DR0=<addr>, DR7 bit 0=1.
//
#include "antidebug/checks/breakpoints/hardware_via_exc.h"
#include "antidebug/checks/breakpoints/hardware.h"  // old check for comparison

__declspec(dllimport) void  __stdcall OutputDebugStringA(const char*);
__declspec(dllimport) void  __stdcall Sleep(unsigned long);
__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int   __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) void* __stdcall CreateFileA(const char*, unsigned long, unsigned long,
                                                   void*, unsigned long, unsigned long, void*);

static void put(const char* s) {
    int n = 0; const char* p = s;
    while (*p) { n++; p++; }
    static void* h = 0;
    if (!h) h = GetStdHandle((unsigned long)-11);
    unsigned long w = 0;
    if (h) WriteFile(h, s, (unsigned long)n, &w, 0);
    OutputDebugStringA(s);

    // Persistent log file so the MCP driver can read results back.
    static void* hLog = 0;
    if (!hLog) {
        hLog = CreateFileA("C:\\temp\\hwe_result.txt",
                           0x40000000UL,  // GENERIC_WRITE
                           3UL,           // FILE_SHARE_READ|WRITE
                           (void*)0,
                           2UL,           // CREATE_ALWAYS
                           0x80UL,        // FILE_ATTRIBUTE_NORMAL
                           (void*)0);
        if (hLog == (void*)(unsigned long long)-1) hLog = 0;
    }
    if (hLog) {
        unsigned long lw = 0;
        WriteFile(hLog, s, (unsigned long)n, &lw, 0);
    }
}

static void hex64(char* out, unsigned long long v) {
    int i;
    out[0] = '0'; out[1] = 'x';
    for (i = 0; i < 16; i++) {
        unsigned n = (unsigned)((v >> ((15 - i) * 4)) & 0xF);
        out[2 + i] = (char)(n < 10 ? '0' + n : 'a' + (n - 10));
    }
    out[18] = 0;
}

static void dump(const char* tag, const ad_hwe_result_t* r) {
    char hx[32], line[96];
    int i, j;
    put(tag);
    put("\n");

    const char* fields[7] = { "  DR0=", "  DR1=", "  DR2=", "  DR3=", "  DR7=",
                               "  CF =", "  EC =" };
    u64 vals[7] = { r->dr0, r->dr1, r->dr2, r->dr3, r->dr7,
                    (u64)r->ctx_flags, (u64)r->exc_code };
    for (i = 0; i < 7; i++) {
        hex64(hx, vals[i]);
        const char* pref = fields[i];
        int plen = 0; while (pref[plen]) plen++;
        for (j = 0; j < plen; j++) line[j] = pref[j];
        for (j = 0; j < 18; j++) line[plen + j] = hx[j];
        line[plen + 18] = '\n'; line[plen + 19] = 0;
        put(line);
    }
    put(r->detected ? "  verdict=DETECTED\n" : "  verdict=clean\n");
}

int main(void) {
    ad_hwe_result_t r;

    put("[HWE] === TEST START ===\n");

    // --- stage 1: CLEAN ---
    ad_hardware_bp_via_exception_ex(&r);
    dump("[HWE] STAGE_CLEAN (exception path)", &r);
    b32 old_clean = ad_hardware_breakpoints();
    put(old_clean ? "[HWE] STAGE_CLEAN (old NtGetContextThread)  : 1\n"
                  : "[HWE] STAGE_CLEAN (old NtGetContextThread)  : 0\n");

    // --- stage 2: arm window (MCP driver sets HWBP during this sleep) ---
    put("[HWE] === ARM WINDOW 20s — setting HWBP now ===\n");
    Sleep(20000);

    // --- stage 3: WITH HWBP ---
    put("[HWE] === POST-ARM ===\n");
    ad_hardware_bp_via_exception_ex(&r);
    dump("[HWE] STAGE_HWBP (exception path)", &r);
    b32 old_armed = ad_hardware_breakpoints();
    put(old_armed ? "[HWE] STAGE_HWBP  (old NtGetContextThread)  : 1  (NOT spoofed)\n"
                  : "[HWE] STAGE_HWBP  (old NtGetContextThread)  : 0  (SPOOFED by ScyllaHide)\n");

    put("[HWE] === VERDICT ===\n");
    if (!old_armed && r.detected) {
        put("[HWE] BYPASS PROVEN: old check blinded, exception path saw real DR values\n");
    } else if (old_armed && r.detected) {
        put("[HWE] both checks fired (ScyllaHide not active or not effective)\n");
    } else if (!old_armed && !r.detected) {
        put("[HWE] NO HWBP SEEN — maybe MCP driver didn't set it, or ScyllaHide hooks KiUserExceptionDispatcher too\n");
    } else {
        put("[HWE] unexpected combo: old=1 new=0 — investigate\n");
    }

    put("[HWE] === TEST END ===\n");
    Sleep(1500);
    return 0;
}
