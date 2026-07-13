// ===== file: tests/test_gw.c =====
//
// Guardian Watchdog harness. Starts the background thread, verifies:
//   1. Heartbeat advances over time
//   2. Main thread's dead-man verify returns 1 while alive
//   3. Suspending the thread triggers tamper on next heartbeat verify
//
#include "antidebug/core/guardian_watchdog.h"

__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int   __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) void  __stdcall OutputDebugStringA(const char*);

static void put(const char* s) {
    int n = 0; const char* p = s;
    while (*p) { n++; p++; }
    static void* h = 0;
    if (!h) h = GetStdHandle((unsigned long)-11);
    unsigned long w = 0;
    if (h) WriteFile(h, s, (unsigned long)n, &w, 0);
    OutputDebugStringA(s);
}

static void u64_dec(char* out, unsigned long long v) {
    char tmp[32]; int i = 0;
    if (!v) { out[0] = '0'; out[1] = 0; return; }
    while (v) { tmp[i++] = (char)('0' + (v % 10ULL)); v /= 10ULL; }
    int j; for (j = 0; j < i; j++) out[j] = tmp[i - 1 - j];
    out[i] = 0;
}

NOINLINE static int p_chk_A(void) { volatile int x = 1; return x ^ 0x1111; }
NOINLINE static int p_chk_B(void) { volatile int x = 2; return x ^ 0x2222; }
NOINLINE static int p_chk_C(void) { volatile int x = 3; return x ^ 0x3333; }
NOINLINE static int p_chk_D(void) { volatile int x = 4; return x ^ 0x4444; }

int main(void) {
    put("[GW] === TEST START ===\n");

    static ad_gm_matrix_t M;
    int k; for (k = 0; k < (int)sizeof(M); k++)
        ((volatile unsigned char*)&M)[k] = 0;

    void* fns[4] = {
        (void*)p_chk_A, (void*)p_chk_B, (void*)p_chk_C, (void*)p_chk_D,
    };
    if (!ad_gm_init(&M, fns, 4)) { put("[GW] matrix init failed\n"); return 1; }

    static ad_gw_ctx_t W;
    if (!ad_gw_start(&W, &M)) { put("[GW] watchdog start failed\n"); return 1; }
    put("[GW] watchdog started\n");

    // Give it a few heartbeats.
    Sleep(600);

    {
        char line[64], num[32]; int i = 0, j;
        const char* p = "[GW] heartbeat after 600ms = ";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        u64_dec(num, W.heartbeat);
        for (j = 0; num[j]; j++) line[i++] = num[j];
        line[i++] = '\n'; line[i] = 0; put(line);
    }

    // Main-thread verify — should be healthy.
    for (k = 0; k < 5; k++) {
        Sleep(200);
        b32 ok = ad_gw_verify_heartbeat(&W);
        put(ok ? "[GW]   heartbeat verify OK\n"
               : "[GW]   heartbeat verify FAIL (unexpected)\n");
    }

    put("[GW] seed before stop = ");
    {
        char hx[32]; int i; unsigned long long v = ad_gm_crypto_seed(&M);
        hx[0] = '0'; hx[1] = 'x';
        for (i = 0; i < 16; i++) {
            unsigned n = (unsigned)((v >> ((15 - i) * 4)) & 0xF);
            hx[2 + i] = (char)(n < 10 ? '0' + n : 'a' + (n - 10));
        }
        hx[18] = '\n'; hx[19] = 0;
        put(hx);
    }

    // DEAD-MAN : stop the watchdog → heartbeat stops advancing.
    put("[GW] stopping watchdog (simulating attacker suspending it)\n");
    ad_gw_stop(&W);
    // Wait for thread to exit
    Sleep(400);

    // First verify post-stop: may see residual advance and reset the
    // baseline — that's fine. Subsequent calls observe no advance past
    // the baseline for > TIMEOUT → fire.
    (void)ad_gw_verify_heartbeat(&W);   // consume any residual advance
    Sleep(AD_GW_HEARTBEAT_TIMEOUT_MS + 500u);

    b32 ok2 = ad_gw_verify_heartbeat(&W);
    put(ok2 ? "[GW] post-stop verify unexpectedly OK\n"
            : "[GW] post-stop verify FIRED — tamper propagated\n");

    put("[GW] seed after dead-man = ");
    {
        char hx[32]; int i; unsigned long long v = ad_gm_crypto_seed(&M);
        hx[0] = '0'; hx[1] = 'x';
        for (i = 0; i < 16; i++) {
            unsigned n = (unsigned)((v >> ((15 - i) * 4)) & 0xF);
            hx[2 + i] = (char)(n < 10 ? '0' + n : 'a' + (n - 10));
        }
        hx[18] = '\n'; hx[19] = 0;
        put(hx);
    }
    put(ad_gm_is_tampered(&M) ? "[GW] matrix tampered=1 (EXPECTED after dead-man)\n"
                              : "[GW] matrix tampered=0 (unexpected)\n");

    put("[GW] === TEST END ===\n");
    return 0;
}
