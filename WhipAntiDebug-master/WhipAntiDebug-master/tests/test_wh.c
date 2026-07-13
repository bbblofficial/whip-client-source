// ===== file: tests/test_wh.c =====
//
// Whip Hostile harness. Validates each countermeasure fires ONLY after
// tamper and stays silent before.
//
// For the test, we DISABLE suicide (otherwise test exits) and limit
// slowdown to a token 50 ms so the test completes promptly.
//
#define AD_WH_ENABLE_SUICIDE   0
#define AD_WH_SLOWDOWN_MIN_MS  30u
#define AD_WH_SLOWDOWN_MAX_MS  100u
#include "antidebug/core/whip_hostile.h"

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

NOINLINE static int p_chk_A(void) { volatile int x = 1; return x ^ 0x1111; }
NOINLINE static int p_chk_B(void) { volatile int x = 2; return x ^ 0x2222; }
NOINLINE static int p_chk_C(void) { volatile int x = 3; return x ^ 0x3333; }

int main(void) {
    put("[WH] === TEST START ===\n");

    static ad_gm_matrix_t M;
    int k; for (k = 0; k < (int)sizeof(M); k++)
        ((volatile unsigned char*)&M)[k] = 0;
    void* fns[3] = { (void*)p_chk_A, (void*)p_chk_B, (void*)p_chk_C };
    if (!ad_gm_init(&M, fns, 3)) { put("matrix init failed\n"); return 1; }

    static ad_wh_ctx_t H;
    if (!ad_wh_init(&H, &M)) { put("hostile init failed\n"); return 1; }
    put("[WH] hostile init ok\n");

    // --- STAGE_CLEAN : 10 ticks, should be instant + silent.
    put("[WH] STAGE_CLEAN: 10 ticks...\n");
    unsigned long t0 = GetTickCount();
    for (k = 0; k < 10; k++) ad_wh_tick(&H);
    unsigned long t1 = GetTickCount();
    {
        char line[64]; int i = 0, j;
        const char* p = "[WH]   elapsed=";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        unsigned long d = t1 - t0;
        if (d >= 100) line[i++] = (char)('0' + ((d / 100) % 10));
        if (d >= 10)  line[i++] = (char)('0' + ((d / 10) % 10));
        line[i++] = (char)('0' + (d % 10));
        const char* p2 = " ms (should be 0-1)\n";
        for (j = 0; p2[j]; j++) line[i++] = p2[j];
        line[i] = 0; put(line);
    }

    // --- FORCE TAMPER
    put("[WH] forcing tamper...\n");
    ad_gm_mark_tamper(&M);

    // --- STAGE_HOSTILE : 5 ticks, expect ~150-500ms total (3 slowdowns × 30-100ms)
    put("[WH] STAGE_HOSTILE: 5 ticks post-tamper (expect slowdown, ODS spam, etc.)\n");
    t0 = GetTickCount();
    for (k = 0; k < 5; k++) {
        ad_wh_tick(&H);
    }
    t1 = GetTickCount();
    {
        char line[64]; int i = 0, j;
        const char* p = "[WH]   elapsed=";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        unsigned long d = t1 - t0;
        if (d >= 100) line[i++] = (char)('0' + ((d / 100) % 10));
        if (d >= 10)  line[i++] = (char)('0' + ((d / 10) % 10));
        line[i++] = (char)('0' + (d % 10));
        const char* p2 = " ms (should be 150-500)\n";
        for (j = 0; p2[j]; j++) line[i++] = p2[j];
        line[i] = 0; put(line);
    }

    put("[WH] Note: check ODS output for 5 fake-finding messages and\n");
    put("[WH] if run under x64dbg, you should have seen 5 first-chance\n");
    put("[WH] breaks on exception code 0xE0DEADC0 during the hostile stage.\n");
    put("[WH] === TEST END ===\n");
    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllimport) unsigned long __stdcall GetTickCount(void);
#ifdef __cplusplus
}
#endif
