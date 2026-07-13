// ===== file: tests/test_tsc_qpc_drift.c =====
//
// TSC/QPC drift check harness.
//
// STAGE_CALIBRATE : 50 ms calibration, prints ratio
// STAGE_CLEAN     : 5 consecutive checks, all should be 0, drifts low
// STAGE_X64DBG    : 15 s sleep; attach x64dbg, set a HWBP somewhere, run,
//                   then run the final check. Expected: drift blown up
//                   if debugger events perturb the QPC source.
//
#include "antidebug/checks/timing/tsc_qpc_drift.h"

__declspec(dllimport) void  __stdcall OutputDebugStringA(const char* s);
__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long nStdHandle);
__declspec(dllimport) int   __stdcall WriteFile(void* hFile, const void* buf,
                                                 unsigned long n,
                                                 unsigned long* written,
                                                 void* overlapped);

static void put(const char* s) {
    int len = 0; const char* p = s;
    while (*p) { len++; p++; }
    static void* h = 0;
    if (!h) h = GetStdHandle((unsigned long)-11);
    unsigned long w = 0;
    if (h) WriteFile(h, s, (unsigned long)len, &w, 0);
    OutputDebugStringA(s);
}

static void u64_to_dec(char* out, unsigned long long v) {
    char tmp[32];
    int i = 0;
    if (v == 0) { out[0] = '0'; out[1] = 0; return; }
    while (v) { tmp[i++] = (char)('0' + (v % 10ULL)); v /= 10ULL; }
    int j;
    for (j = 0; j < i; j++) out[j] = tmp[i - 1 - j];
    out[i] = 0;
}

int main(void) {
    char num[32], line[128];
    int i, j;

    ad_tsc_qpc_ctx_t ctx;
    for (i = 0; i < (int)sizeof(ctx); i++)
        ((volatile unsigned char*)&ctx)[i] = 0;

    put("[DRIFT] calibrating...\n");
    ad_tsc_qpc_calibrate(&ctx);
    if (!ctx.calibrated) {
        put("[DRIFT] STAGE_CALIBRATE failed\n");
        return 1;
    }
    u64_to_dec(num, ctx.tsc_per_qpc_q16);
    const char* p = "[DRIFT] STAGE_CALIBRATE ratio_q16=";
    int n = 0; while (p[n]) n++;
    for (j = 0; j < n; j++) line[j] = p[j];
    int nn = 0; while (num[nn]) { line[n + nn] = num[nn]; nn++; }
    line[n + nn] = '\n'; line[n + nn + 1] = 0;
    put(line);

    // --- stage clean: 5 consecutive checks --------------------------------
    int hits = 0;
    for (i = 0; i < 5; i++) {
        u64 pct = ad_tsc_qpc_drift_pct(&ctx);
        b32 v = ad_tsc_qpc_drift_check(&ctx);
        if (v) hits++;
        u64_to_dec(num, pct);
        const char* q = "[DRIFT] STAGE_CLEAN pct=";
        n = 0; while (q[n]) n++;
        for (j = 0; j < n; j++) line[j] = q[j];
        nn = 0; while (num[nn]) { line[n + nn] = num[nn]; nn++; }
        line[n + nn] = ' ';
        line[n + nn + 1] = 'v'; line[n + nn + 2] = '=';
        line[n + nn + 3] = (char)('0' + v);
        line[n + nn + 4] = '\n'; line[n + nn + 5] = 0;
        put(line);
    }
    put(hits == 0 ? "[DRIFT] STAGE_CLEAN 5/5 negative (OK)\n"
                  : "[DRIFT] STAGE_CLEAN false-positive (investigate)\n");

    // --- stage x64dbg -----------------------------------------------------
    __declspec(dllimport) void __stdcall Sleep(unsigned long);
    put("[DRIFT] sleeping 15s — attach x64dbg, pause/resume a few times, then wait.\n");
    Sleep(15000);

    u64 final_pct = ad_tsc_qpc_drift_pct(&ctx);
    b32 final = ad_tsc_qpc_drift_check(&ctx);
    u64_to_dec(num, final_pct);
    const char* r = "[DRIFT] STAGE_X64DBG pct=";
    n = 0; while (r[n]) n++;
    for (j = 0; j < n; j++) line[j] = r[j];
    nn = 0; while (num[nn]) { line[n + nn] = num[nn]; nn++; }
    line[n + nn] = ' '; line[n + nn + 1] = 'v'; line[n + nn + 2] = '=';
    line[n + nn + 3] = (char)('0' + final);
    line[n + nn + 4] = '\n'; line[n + nn + 5] = 0;
    put(line);

    Sleep(1500);
    return 0;
}
