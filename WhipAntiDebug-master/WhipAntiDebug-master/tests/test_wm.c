// ===== file: tests/test_wm.c =====
//
// Whip Meta harness — validates honey, cross-val, call-counter, self-test.
//
#include "antidebug/core/whip_meta.h"

__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int   __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) void  __stdcall OutputDebugStringA(const char*);
__declspec(dllimport) int   __stdcall VirtualProtect(void*, u64, unsigned long, unsigned long*);

static void put(const char* s) {
    int n = 0; const char* p = s;
    while (*p) { n++; p++; }
    static void* h = 0;
    if (!h) h = GetStdHandle((unsigned long)-11);
    unsigned long w = 0;
    if (h) WriteFile(h, s, (unsigned long)n, &w, 0);
    OutputDebugStringA(s);
}

// Dummy checks.
static u32 chk_always0(void* c) { (void)c; return 0u; }
static u32 chk_always1(void* c) { (void)c; return 1u; }

// "Twin" pair: logically always agree.
static volatile u32 g_twin_state = 0u;
static u32 chk_twin_A(void* c) { (void)c; return g_twin_state; }
static u32 chk_twin_B(void* c) { (void)c; return g_twin_state; }

NOINLINE static int p_chk_A(void) { volatile int x = 1; return x ^ 0x1111; }
NOINLINE static int p_chk_B(void) { volatile int x = 2; return x ^ 0x2222; }
NOINLINE static int p_chk_C(void) { volatile int x = 3; return x ^ 0x3333; }

int main(void) {
    put("[WM] === TEST START ===\n");

    static ad_gm_matrix_t   MX;
    static ad_gmeta_ctx_t   MT;
    int k; for (k = 0; k < (int)sizeof(MX); k++) ((volatile unsigned char*)&MX)[k] = 0;
    for (k = 0; k < (int)sizeof(MT); k++) ((volatile unsigned char*)&MT)[k] = 0;

    void* fns[3] = { (void*)p_chk_A, (void*)p_chk_B, (void*)p_chk_C };
    if (!ad_gm_init(&MX, fns, 3)) { put("matrix init failed\n"); return 1; }
    if (!ad_gmeta_init(&MT, &MX)) { put("meta init failed\n"); return 1; }

    static ad_wm_ctx_t CTX;
    ad_wm_init(&CTX, &MX, &MT);

    u32 slot_A = ad_wm_register(&CTX, chk_always0, 0, 0xAAAA, 5);
    u32 slot_B = ad_wm_register(&CTX, chk_twin_A, 0, 0xBBBB, 5);
    u32 slot_C = ad_wm_register(&CTX, chk_twin_B, 0, 0xCCCC, 5);
    u32 slot_D = ad_wm_register(&CTX, chk_always1, 0, 0xDDDD, 10);
    (void)slot_A; (void)slot_D;

    // Twins must agree.
    ad_wm_register_xval(&CTX, slot_B, slot_C);

    // --- STAGE_CLEAN ---
    {
        ad_wm_verdict_t v;
        ad_wm_evaluate(&CTX, &v);
        char line[160]; int i = 0, j;
        const char* p = "[WM] STAGE_CLEAN  honey=";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        line[i++] = (char)('0' + v.honey_ok);
        const char* p2 = "  selftest=";
        for (j = 0; p2[j]; j++) line[i++] = p2[j];
        line[i++] = (char)('0' + v.selftest_ok);
        const char* p3 = "  xval_fail=";
        for (j = 0; p3[j]; j++) line[i++] = p3[j];
        line[i++] = (char)('0' + v.xval_failures);
        const char* p4 = "  ctr_min=";
        for (j = 0; p4[j]; j++) line[i++] = p4[j];
        line[i++] = (char)('0' + v.counter_min);
        const char* p5 = " ctr_max=";
        for (j = 0; p5[j]; j++) line[i++] = p5[j];
        line[i++] = (char)('0' + v.counter_max);
        const char* p6 = " meta_tamper=";
        for (j = 0; p6[j]; j++) line[i++] = p6[j];
        line[i++] = (char)('0' + v.meta_tamper);
        const char* p7 = " score=";
        for (j = 0; p7[j]; j++) line[i++] = p7[j];
        line[i++] = (char)('0' + (v.aggregate_score / 10));
        line[i++] = (char)('0' + (v.aggregate_score % 10));
        line[i++] = '\n'; line[i] = 0; put(line);
    }

    // --- STAGE_TWIN_DIVERGE : break twin consistency ---
    put("[WM] STAGE_TWIN_DIVERGE: force twin B to report 1 while A reports 0\n");
    // Only patch chk_twin_B to always return 1. Walk over chk_twin_A.
    // Easiest: replace the function pointer with chk_always1 for B.
    CTX.slots[slot_C].fn = chk_always1;
    {
        ad_wm_verdict_t v;
        ad_wm_evaluate(&CTX, &v);
        char line[160]; int i = 0, j;
        const char* p = "[WM] STAGE_DIVERGE xval_fail=";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        line[i++] = (char)('0' + v.xval_failures);
        const char* p2 = " meta_tamper=";
        for (j = 0; p2[j]; j++) line[i++] = p2[j];
        line[i++] = (char)('0' + v.meta_tamper);
        const char* p3 = " tampered(matrix)=";
        for (j = 0; p3[j]; j++) line[i++] = p3[j];
        line[i++] = (char)('0' + ad_gm_is_tampered(&MX));
        line[i++] = '\n'; line[i] = 0; put(line);
    }

    // --- STAGE_HONEY_PATCH : replace honey fn with always-0 ---
    put("[WM] STAGE_HONEY_PATCH: overwrite honey fn pointer\n");
    CTX.slots[0].fn = chk_always0;
    {
        ad_wm_verdict_t v;
        ad_wm_evaluate(&CTX, &v);
        char line[160]; int i = 0, j;
        const char* p = "[WM] STAGE_HONEY   honey_ok=";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        line[i++] = (char)('0' + v.honey_ok);
        const char* p2 = " meta_tamper=";
        for (j = 0; p2[j]; j++) line[i++] = p2[j];
        line[i++] = (char)('0' + v.meta_tamper);
        line[i++] = '\n'; line[i] = 0; put(line);
    }

    put("[WM] === TEST END ===\n");
    return 0;
}
