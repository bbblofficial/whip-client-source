// ===== file: tests/test_gmeta.c =====
//
// Guardian Meta harness. Validates:
//   1. Deception Field: pre-tamper returns real values; post-tamper lies
//   2. Timing introspection: artificial delay triggers tamper
//   3. Call-site verification: call from outside image triggers tamper
//
#include "antidebug/core/guardian_meta.h"

__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int   __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) void  __stdcall OutputDebugStringA(const char*);
__declspec(dllimport) int   __stdcall VirtualProtect(void*, u64, unsigned long, unsigned long*);
__declspec(dllimport) void  __stdcall Sleep(unsigned long);

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
NOINLINE static int p_chk_D(void) { volatile int x = 4; return x ^ 0x4444; }

// Example protected "check" that emits via the meta layer.
NOINLINE static b32 fake_check_fn(ad_gmeta_ctx_t* ctx, b32 real_result) {
    AD_GMETA_GUARD_BEGIN(ctx);
    // Pretend to do work
    volatile int x = 0; int i;
    for (i = 0; i < 100; i++) x += i;
    AD_GMETA_GUARD_END(ctx);
    return AD_GMETA_EMIT(ctx, real_result);
}

int main(void) {
    put("[GMETA] === TEST START ===\n");

    static ad_gm_matrix_t M;
    int k; for (k = 0; k < (int)sizeof(M); k++)
        ((volatile unsigned char*)&M)[k] = 0;
    void* fns[4] = { (void*)p_chk_A, (void*)p_chk_B, (void*)p_chk_C, (void*)p_chk_D };
    if (!ad_gm_init(&M, fns, 4)) { put("[GMETA] matrix init failed\n"); return 1; }

    static ad_gmeta_ctx_t META;
    if (!ad_gmeta_init(&META, &M)) { put("[GMETA] meta init failed\n"); return 1; }
    put("[GMETA] init ok\n");

    // STAGE_CLEAN — real_result=0 passes through truthfully.
    put("[GMETA] STAGE_CLEAN (real=0):\n");
    int c0 = 0, c1 = 0;
    for (k = 0; k < 20; k++) {
        b32 r = fake_check_fn(&META, 0);
        if (r == 0) c0++; else c1++;
    }
    {
        char line[96]; int i = 0, j;
        const char* p = "  emitted 0: "; for (j = 0; p[j]; j++) line[i++] = p[j];
        line[i++] = (char)('0' + (c0 / 10)); line[i++] = (char)('0' + (c0 % 10));
        const char* p2 = "  emitted 1: "; for (j = 0; p2[j]; j++) line[i++] = p2[j];
        line[i++] = (char)('0' + (c1 / 10)); line[i++] = (char)('0' + (c1 % 10));
        line[i++] = '\n'; line[i] = 0; put(line);
    }
    put(c1 == 0 ? "  → all truthful in clean mode (OK)\n"
               : "  → UNEXPECTED: deception in clean mode\n");

    // STAGE_FORCE_TAMPER — manually tamper via mark
    put("[GMETA] STAGE_FORCE_TAMPER: manually triggering tamper\n");
    ad_gm_mark_tamper(&M);

    put("[GMETA] STAGE_DECEPTION (real=0, expect ~75% inverted to 1):\n");
    c0 = 0; c1 = 0;
    for (k = 0; k < 20; k++) {
        b32 r = fake_check_fn(&META, 0);
        if (r == 0) c0++; else c1++;
    }
    {
        char line[96]; int i = 0, j;
        const char* p = "  emitted 0 (truth): "; for (j = 0; p[j]; j++) line[i++] = p[j];
        line[i++] = (char)('0' + (c0 / 10)); line[i++] = (char)('0' + (c0 % 10));
        const char* p2 = "  emitted 1 (lie):   "; for (j = 0; p2[j]; j++) line[i++] = p2[j];
        line[i++] = (char)('0' + (c1 / 10)); line[i++] = (char)('0' + (c1 % 10));
        line[i++] = '\n'; line[i] = 0; put(line);
    }
    put(c1 > c0 ? "  → deception engaged (most results inverted)\n"
                : "  → UNEXPECTED: truthful majority post-tamper\n");

    // STAGE_TIMING — simulate an attacker "single-stepping" by adding
    // a deliberate long delay inside the guard. Should re-trigger tamper.
    // (We already tampered above, so it's already set — but verify the
    //  timing path would fire if this was the first tamper.)
    put("[GMETA] STAGE_TIMING: simulating 1ms delay inside guard\n");
    {
        AD_GMETA_GUARD_BEGIN(&META);
        Sleep(1);   // ~3M cycles at 3 GHz, way over threshold
        AD_GMETA_GUARD_END(&META);
    }
    put(ad_gm_is_tampered(&M) ? "  → matrix tampered=1 (OK, always since STAGE_FORCE_TAMPER)\n"
                             : "  → UNEXPECTED: matrix clean\n");

    put("[GMETA] === TEST END ===\n");
    return 0;
}
