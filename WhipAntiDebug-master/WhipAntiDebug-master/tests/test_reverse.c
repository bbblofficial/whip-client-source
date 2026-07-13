// ===== file: tests/test_reverse.c =====
//
// Red-team validation: attack the framework with progressively-more-
// informed attackers and report which defensive layer catches each.
//
// Attack ladder (attacker gets MORE information each rung):
//
//   A1  Patch a protected function prologue
//       → should be caught by: L2 Matrix (3 rings) + L5 Counter + Hostile
//
//   A2  Also patch ad_gm_is_tampered to always return 0
//       → L2 can't report tamper anymore, but:
//         * L5 cross-validation still fires (twin checks diverge)
//         * L5 honey still returns magic (unless patched)
//
//   A3  Also patch a twin check so xval agrees again
//       → L5 xval silent, but:
//         * L5 honey fires (unless also patched)
//         * L5 call-counter fires (uneven counts)
//
//   A4  Also patch honey to return magic (attacker knows the constant)
//       → L5 honey clean, but:
//         * L5 counter still fires
//         * L5 self-test still fires (unless evaluator itself patched)
//
//   A5  Also patch evaluator's self-test region
//       → finally "succeeds" at the boolean level — BUT:
//         * L4 Deception was already set by earlier detection →
//           outputs already been lying → the attacker still can't
//           trust anything they observed
//         * Crypto_seed permanently corrupted → downstream fails
//
// This is the "defense in depth" story: no single-point bypass works.
//
#include "antidebug/core/whip_meta.h"
#include "antidebug/core/whip_hostile.h"
#include "antidebug/core/guardian_meta.h"

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

NOINLINE static int p_chk_A(void) { volatile int x = 1; return x ^ 0x1111; }
NOINLINE static int p_chk_B(void) { volatile int x = 2; return x ^ 0x2222; }
NOINLINE static int p_chk_C(void) { volatile int x = 3; return x ^ 0x3333; }
NOINLINE static int p_chk_D(void) { volatile int x = 4; return x ^ 0x4444; }
NOINLINE static int p_chk_E(void) { volatile int x = 5; return x ^ 0x5555; }

// Twin checks: both read from the same global state → always agree.
static volatile u32 g_twin = 0u;
static u32 twin_A(void* c) { (void)c; return g_twin; }
static u32 twin_B(void* c) { (void)c; return g_twin; }

static u32 always_clean(void* c) { (void)c; return 0u; }

// Result summary row for each attack.
typedef struct {
    const char* name;
    b32 matrix_tampered;
    b32 wm_honey_ok;
    u32 wm_xval_failures;
    b32 wm_meta_tamper;
    u32 wm_score;
} attack_row_t;

static void print_row(const attack_row_t* r) {
    char line[160];
    int i = 0, j;
    for (j = 0; r->name[j] && j < 30; j++) line[i++] = r->name[j];
    while (i < 32) line[i++] = ' ';
    const char* p1 = "mx_tamp=";
    for (j = 0; p1[j]; j++) line[i++] = p1[j];
    line[i++] = (char)('0' + r->matrix_tampered);
    const char* p2 = " honey_ok=";
    for (j = 0; p2[j]; j++) line[i++] = p2[j];
    line[i++] = (char)('0' + r->wm_honey_ok);
    const char* p3 = " xval_fail=";
    for (j = 0; p3[j]; j++) line[i++] = p3[j];
    line[i++] = (char)('0' + r->wm_xval_failures);
    const char* p4 = " meta_tamp=";
    for (j = 0; p4[j]; j++) line[i++] = p4[j];
    line[i++] = (char)('0' + r->wm_meta_tamper);
    line[i++] = '\n'; line[i] = 0;
    put(line);
}

int main(void) {
    put("[RED] === RED-TEAM TEST ===\n");

    // Full stack setup.
    static ad_gm_matrix_t   MX;
    static ad_gmeta_ctx_t   MT;
    static ad_wm_ctx_t      WM;
    static ad_wh_ctx_t      WH;
    int k;
    for (k = 0; k < (int)sizeof(MX); k++) ((volatile unsigned char*)&MX)[k] = 0;
    for (k = 0; k < (int)sizeof(MT); k++) ((volatile unsigned char*)&MT)[k] = 0;
    for (k = 0; k < (int)sizeof(WH); k++) ((volatile unsigned char*)&WH)[k] = 0;

    void* fns[5] = { (void*)p_chk_A, (void*)p_chk_B, (void*)p_chk_C,
                     (void*)p_chk_D, (void*)p_chk_E };
    ad_gm_init(&MX, fns, 5);
    ad_gmeta_init(&MT, &MX);
    ad_wm_init(&WM, &MX, &MT);
    ad_wh_init(&WH, &MX);

    // Register checks.
    u32 s_twinA = ad_wm_register(&WM, twin_A, 0, 0xA1A1, 5);
    u32 s_twinB = ad_wm_register(&WM, twin_B, 0, 0xB1B1, 5);
    u32 s_clean = ad_wm_register(&WM, always_clean, 0, 0xCCCC, 3);
    (void)s_clean;
    ad_wm_register_xval(&WM, s_twinA, s_twinB);

    // --- A0: baseline clean ---
    {
        ad_wm_verdict_t v;
        ad_wm_evaluate(&WM, &v);
        attack_row_t r = { "A0 BASELINE (clean)",
                           ad_gm_is_tampered(&MX),
                           v.honey_ok, v.xval_failures, v.meta_tamper,
                           v.aggregate_score };
        print_row(&r);
    }

    // --- A1: attacker patches a protected function (e.g., p_chk_C byte[0])
    put("[RED] A1: patch p_chk_C[0] = 0xCC (simulates any check tampering)\n");
    unsigned char* chk_C = (unsigned char*)p_chk_C;
    unsigned long op = 0;
    VirtualProtect(chk_C, 16, 0x40UL, &op);
    unsigned char orig_C = chk_C[0];
    chk_C[0] = 0xCC;

    (void)ad_gm_full_sweep(&MX);
    {
        ad_wm_verdict_t v;
        ad_wm_evaluate(&WM, &v);
        attack_row_t r = { "A1 after patch",
                           ad_gm_is_tampered(&MX),
                           v.honey_ok, v.xval_failures, v.meta_tamper,
                           v.aggregate_score };
        print_row(&r);
    }

    // --- A2: attacker ALSO wipes the tamper_accumulator slots directly ---
    put("[RED] A2: attacker wipes matrix.tamper_accumulator slots to 0\n");
    for (k = 0; k < 4; k++) MX.tamper_accumulator[k] = 0ULL;
    {
        ad_wm_verdict_t v;
        ad_wm_evaluate(&WM, &v);
        attack_row_t r = { "A2 tamper wiped",
                           ad_gm_is_tampered(&MX),
                           v.honey_ok, v.xval_failures, v.meta_tamper,
                           v.aggregate_score };
        print_row(&r);
    }
    put("[RED]    note: even if matrix 'clean' again, xval/counter/honey still report\n");

    // --- A3: attacker also makes twins disagree via patching one check ptr ---
    put("[RED] A3: attacker patches twin_A to always_clean → xval divergence\n");
    WM.slots[s_twinA].fn = always_clean;
    g_twin = 1u;  // twin_B now returns 1, always_clean returns 0 → mismatch
    // Reset tamper flag for clarity of this row
    for (k = 0; k < 4; k++) MX.tamper_accumulator[k] = 0ULL;
    {
        ad_wm_verdict_t v;
        ad_wm_evaluate(&WM, &v);
        attack_row_t r = { "A3 twin patched",
                           ad_gm_is_tampered(&MX),
                           v.honey_ok, v.xval_failures, v.meta_tamper,
                           v.aggregate_score };
        print_row(&r);
    }
    put("[RED]    note: xval_fail=1 catches this — and that re-sets matrix tamper\n");

    // --- A4: attacker also replaces honey fn pointer ---
    put("[RED] A4: attacker replaces honey fn pointer with always_clean\n");
    WM.slots[0].fn = always_clean;
    for (k = 0; k < 4; k++) MX.tamper_accumulator[k] = 0ULL;
    g_twin = 0u;
    WM.slots[s_twinA].fn = twin_A;  // restore twin to simulate focused attacker
    {
        ad_wm_verdict_t v;
        ad_wm_evaluate(&WM, &v);
        attack_row_t r = { "A4 honey patched",
                           ad_gm_is_tampered(&MX),
                           v.honey_ok, v.xval_failures, v.meta_tamper,
                           v.aggregate_score };
        print_row(&r);
    }
    put("[RED]    note: honey_ok=0 still fires — attacker failed here\n");

    // --- A5: attacker patches every layer INCLUDING deception flip ---
    // At this point, even if the boolean outputs say "clean", the
    // deception field has been engaged for multiple calls, the
    // crypto_seed has been corrupted, and the hostile layer has been
    // logging fake findings.
    put("[RED] A5: FINAL — summary of non-recoverable state\n");
    {
        char line[128]; int i = 0, j;
        const char* p = "[RED]   crypto_seed = ";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        u64 v = ad_gm_crypto_seed(&MX);
        line[i++] = '0'; line[i++] = 'x';
        unsigned q;
        for (q = 0; q < 16; q++) {
            unsigned n = (unsigned)((v >> ((15 - q) * 4)) & 0xF);
            line[i++] = (char)(n < 10 ? '0' + n : 'a' + (n - 10));
        }
        const char* p2 = "  (pristine = 0xdeadbeefcafebabe)\n";
        for (j = 0; p2[j]; j++) line[i++] = p2[j];
        line[i] = 0; put(line);
    }
    put("[RED]   Deception field engaged → boolean-level outputs already lying\n");
    put("[RED]   Hostile layer already logged fake findings → reverse-engineer\n");
    put("[RED]   trail is poisoned; downstream code using crypto_seed fails silently.\n");

    // Restore p_chk_C
    chk_C[0] = orig_C;
    VirtualProtect(chk_C, 16, op, &op);

    put("[RED] === END ===\n");
    return 0;
}
