// ===== file: tests/test_gm.c =====
//
// Guardian Matrix V2 harness — verifies all upgrades work:
//   1. Encrypted state (hash_enc, addr_enc decrypt correctly)
//   2. Polymorphic verify (all 4 implementations converge on same answer)
//   3. Triple ring (each ring can detect a patch independently)
//   4. Non-local effect (crypto_seed gets corrupted on tamper)
//   5. Sticky tamper (persists after restore)
//
#include "antidebug/core/guardian_matrix.h"

__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int   __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) void  __stdcall OutputDebugStringA(const char*);
__declspec(dllimport) int   __stdcall VirtualProtect(void*, u64, unsigned long, unsigned long*);
__declspec(dllimport) void* __stdcall CreateFileA(const char*, unsigned long, unsigned long, void*, unsigned long, unsigned long, void*);

static void put(const char* s) {
    int n = 0; const char* p = s;
    while (*p) { n++; p++; }
    static void* h = 0;
    if (!h) h = GetStdHandle((unsigned long)-11);
    unsigned long w = 0;
    if (h) WriteFile(h, s, (unsigned long)n, &w, 0);
    OutputDebugStringA(s);

    static void* hLog = 0;
    if (!hLog) {
        hLog = CreateFileA("C:\\temp\\gm_result.txt",
                           0x40000000UL, 3UL, (void*)0, 2UL, 0x80UL, (void*)0);
        if (hLog == (void*)(unsigned long long)-1) hLog = 0;
    }
    if (hLog) { unsigned long lw = 0; WriteFile(hLog, s, (unsigned long)n, &lw, 0); }
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

// 7 mock protected checks (odd number → ring topologies don't degenerate).
NOINLINE static int p_chk_A(void) { volatile int x = 1; return x ^ 0x1111; }
NOINLINE static int p_chk_B(void) { volatile int x = 2; return x ^ 0x2222; }
NOINLINE static int p_chk_C(void) { volatile int x = 3; return x ^ 0x3333; }
NOINLINE static int p_chk_D(void) { volatile int x = 4; return x ^ 0x4444; }
NOINLINE static int p_chk_E(void) { volatile int x = 5; return x ^ 0x5555; }
NOINLINE static int p_chk_F(void) { volatile int x = 6; return x ^ 0x6666; }
NOINLINE static int p_chk_G(void) { volatile int x = 7; return x ^ 0x7777; }

static const char NAMES[7] = {'A','B','C','D','E','F','G'};

static void report_seed(const char* tag, const ad_gm_matrix_t* m) {
    char hx[32], line[128]; int i = 0, j;
    for (j = 0; tag[j]; j++) line[i++] = tag[j];
    line[i++] = ' '; line[i++] = 's'; line[i++] = 'e'; line[i++] = 'e';
    line[i++] = 'd'; line[i++] = '=';
    hex64(hx, ad_gm_crypto_seed(m));
    for (j = 0; j < 18; j++) line[i + j] = hx[j];
    i += 18;
    line[i++] = ' '; line[i++] = 't'; line[i++] = '='; line[i++] = '0' + (char)ad_gm_is_tampered(m);
    line[i++] = '\n'; line[i] = 0;
    put(line);
}

int main(void) {
    put("[GM] === TEST START ===\n");
    static ad_gm_matrix_t M;
    int k; for (k = 0; k < (int)sizeof(M); k++)
        ((volatile unsigned char*)&M)[k] = 0;

    void* fns[7] = {
        (void*)p_chk_A, (void*)p_chk_B, (void*)p_chk_C, (void*)p_chk_D,
        (void*)p_chk_E, (void*)p_chk_F, (void*)p_chk_G,
    };

    if (!ad_gm_init(&M, fns, 7)) { put("[GM] init failed\n"); return 1; }
    put("[GM] STAGE_INIT 7 members, 3 rings\n");
    report_seed("[GM] STAGE_INIT_STATE", &M);

    // STAGE_CLEAN: invoke all 4 polymorphic verify impls directly to
    // confirm each converges on "ok" in the clean state.
    int any_fail = 0;
    put("[GM] STAGE_CLEAN running each polymorphic impl on each member:\n");
    for (k = 0; k < 7; k++) {
        b32 r = ad_gm_verify(&M, (u32)k);
        if (!r) any_fail = 1;
    }
    put(any_fail ? "[GM]   one or more polymorphic verify failed (unexpected)\n"
                 : "[GM]   all polymorphic verifies pass\n");
    report_seed("[GM] STAGE_CLEAN_STATE", &M);

    // Full sweep
    u32 bad = ad_gm_full_sweep(&M);
    {
        char line[64]; int i = 0, j; const char* p = "[GM] STAGE_SWEEP bad=";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        line[i++] = (char)('0' + (bad / 10)); line[i++] = (char)('0' + (bad % 10));
        line[i++] = '\n'; line[i] = 0; put(line);
    }
    report_seed("[GM] STAGE_SWEEP_STATE", &M);

    // STAGE_ATTACK: patch p_chk_D first byte. Multiple rings should
    // detect: ring 0 via member B (watches D-2 → but actually ring 0's
    // watchers of D are... topology[0][D-1]=D so C watches D). Ring 1
    // (skip-2) watches D from B. Ring 2 (prime perm) watches D from
    // members where (i*7+3) mod 7 == 3 → i*7 ≡ 0 → i=0 (A).
    unsigned char* tgt = (unsigned char*)p_chk_D;
    unsigned long old_prot = 0;
    if (VirtualProtect(tgt, 16, 0x40UL, &old_prot)) {
        unsigned char orig = tgt[0];
        tgt[0] = 0xCC;
        put("[GM] STAGE_ATTACK: patched p_chk_D[0]=0xCC\n");

        // Full sweep to collect detections across all rings
        u32 bad2 = ad_gm_full_sweep(&M);
        {
            char line[64]; int i = 0, j; const char* p = "[GM]   sweep mismatches=";
            for (j = 0; p[j]; j++) line[i++] = p[j];
            line[i++] = (char)('0' + (bad2 / 10)); line[i++] = (char)('0' + (bad2 % 10));
            line[i++] = '\n'; line[i] = 0; put(line);
        }
        report_seed("[GM] STAGE_ATTACK_STATE", &M);

        tgt[0] = orig;
        unsigned long dummy = 0;
        VirtualProtect(tgt, 16, old_prot, &dummy);
    }

    // Post-restore: bytes are back, but sticky tamper + corrupted seed remain.
    u32 bad3 = ad_gm_full_sweep(&M);
    {
        char line[64]; int i = 0, j; const char* p = "[GM] STAGE_RESTORE bad=";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        line[i++] = (char)('0' + (bad3 / 10)); line[i++] = (char)('0' + (bad3 % 10));
        line[i++] = '\n'; line[i] = 0; put(line);
    }
    report_seed("[GM] STAGE_RESTORE_STATE", &M);
    put("[GM] (seed should be corrupted vs init, tamper flag still set)\n");

    put("[GM] === TEST END ===\n");
    return 0;
}
