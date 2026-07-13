// ===== file: tests/test_gr.c =====
//
// Guardian Ring harness — simulate an attacker patching one of our
// protected check functions, verify the ring detects it.
//
#include "antidebug/core/guardian_ring.h"

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

// Five mock "protected" functions — each simulates a check that verifies
// the ring before running. A real framework would embed ad_gr_verify at
// the start of each genuine check function.
//
// NOINLINE so each lives at a distinct address.

NOINLINE static int protected_check_A(void) {
    volatile int x = 1; return x ^ 0xA5A5;
}
NOINLINE static int protected_check_B(void) {
    volatile int x = 2; return x ^ 0x5A5A;
}
NOINLINE static int protected_check_C(void) {
    volatile int x = 3; return x ^ 0x1234;
}
NOINLINE static int protected_check_D(void) {
    volatile int x = 4; return x ^ 0xDEAD;
}
NOINLINE static int protected_check_E(void) {
    volatile int x = 5; return x ^ 0xBEEF;
}

static void status(const char* tag, const ad_gr_ring_t* r) {
    put(tag);
    put(ad_gr_is_tampered(r) ? "  tampered=1 (DETECTED)\n" : "  tampered=0 (OK)\n");
}

int main(void) {
    put("[GR] === TEST START ===\n");

    static ad_gr_ring_t ring;
    int k; for (k = 0; k < (int)sizeof(ring); k++)
        ((volatile unsigned char*)&ring)[k] = 0;

    void* fns[5] = {
        (void*)protected_check_A,
        (void*)protected_check_B,
        (void*)protected_check_C,
        (void*)protected_check_D,
        (void*)protected_check_E,
    };

    if (!ad_gr_init(&ring, fns, 5)) {
        put("[GR] init failed\n");
        return 1;
    }
    put("[GR] STAGE_INIT ok, ring of 5 members\n");
    status("[GR] STAGE_CLEAN_0  ", &ring);

    // Each member verifies ring integrity before running its critical work.
    int any_fail = 0;
    for (k = 0; k < 5; k++) {
        if (!ad_gr_verify(&ring, (u32)k)) any_fail = 1;
    }
    put(any_fail ? "[GR] STAGE_CLEAN_1 verify FAILED (unexpected)\n"
                 : "[GR] STAGE_CLEAN_1 all 5 verify passes\n");
    status("[GR] STAGE_CLEAN_1  ", &ring);

    // Full sweep
    u32 mm = ad_gr_full_sweep(&ring);
    if (mm == 0) put("[GR] STAGE_CLEAN_SWEEP 0 mismatches\n");
    status("[GR] STAGE_CLEAN_SWEEP ", &ring);

    // --- STAGE_ATTACK : patch byte 0 of protected_check_C (simulating an
    // attacker inserting an INT3 software breakpoint or a jmp rel32).
    unsigned char* target = (unsigned char*)protected_check_C;
    unsigned long old_prot = 0;
    if (VirtualProtect(target, 16, 0x40UL, &old_prot)) {
        unsigned char orig = target[0];
        target[0] = 0xCC;  // INT3 — simulates software BP install

        put("[GR] STAGE_ATTACK: patched protected_check_C byte[0] = 0xCC\n");

        // Run verify from each neighbour — only B (watcher of C) and D
        // (which uses C as its prev-check paranoia target) will fire.
        int detected_by[5] = {0,0,0,0,0};
        for (k = 0; k < 5; k++) {
            if (!ad_gr_verify(&ring, (u32)k)) detected_by[k] = 1;
        }
        char line[96]; int i = 0, j;
        const char* p = "[GR] STAGE_ATTACK detections: ";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        for (k = 0; k < 5; k++) {
            line[i++] = (char)('A' + k);
            line[i++] = detected_by[k] ? '!' : '.';
            line[i++] = ' ';
        }
        line[i++] = '\n'; line[i] = 0;
        put(line);

        status("[GR] STAGE_ATTACK  ", &ring);

        // Restore
        target[0] = orig;
        unsigned long dummy = 0;
        VirtualProtect(target, 16, old_prot, &dummy);
    }

    // Tamper flag is STICKY — even after restore it stays set.
    u32 mm2 = ad_gr_full_sweep(&ring);
    put(mm2 == 0 ? "[GR] STAGE_RESTORE bytes restored, 0 live mismatches\n"
                 : "[GR] STAGE_RESTORE bytes still differ\n");
    status("[GR] STAGE_RESTORE ", &ring);
    put("(tamper flag is sticky — stays set after restoration)\n");

    put("[GR] === TEST END ===\n");
    return 0;
}
