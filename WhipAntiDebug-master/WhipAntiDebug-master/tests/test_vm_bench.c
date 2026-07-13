#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "../antidebug/core/types.h"
#include "../antidebug/core/macros.h"
#include "../antidebug/vm/vm_interp.h"
#include "../antidebug/vm/vm_programs.h"

// Compare two bytecode buffers, return number of differing bytes
static int diff_bytes(const u8* a, const u8* b, u32 len) {
    int d = 0;
    for (u32 i = 0; i < len; i++) {
        if (a[i] != b[i]) d++;
    }
    return d;
}

int main(void) {
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    u32 rt_key = vm_runtime_key();

    // ================================================================
    // 1. POLYMORPHISM PROOF — build 5 times, compare bytecode
    // ================================================================
    printf("=== Polymorphism Proof ===\n");
    u8 builds[5][1024];
    u32 lens[5];
    u32 steps_dk[5], steps_xd[5];

    for (int i = 0; i < 5; i++) {
        memset(builds[i], 0, 1024);
        lens[i] = vm_build_derive_key(builds[i], rt_key);

        // Also run to verify correctness
        u8 data[128];
        memset(data, 0, sizeof(data));
        vm_state_t vm;
        vm_init(&vm, data);
        vm_shuffle_table(vm.sem_table, rt_key);
        vm.regs[0] = vm_score_encode(0, rt_key);
        __try { vm_run(&vm, builds[i], lens[i], vm_enc_key(rt_key)); } __except(1) {}
        steps_dk[i] = vm.step_count;

        // xor_decrypt
        u8 xcode[1024];
        memset(xcode, 0, 1024);
        u32 xlen = vm_build_xor_decrypt(xcode, rt_key);
        u8 work[192];
        memset(work, 0, sizeof(work));
        for (int j = 0; j < 35; j++) work[j] = (u8)(j * 7 + 3);
        for (int j = 0; j < 35; j++) work[64 + j] = (u8)(j * 13 + 5);
        vm_state_t vm2;
        vm_init(&vm2, work);
        vm_shuffle_table(vm2.sem_table, rt_key);
        vm2.regs[0] = 35;
        vm_run(&vm2, xcode, xlen, vm_enc_key(rt_key));
        steps_xd[i] = vm2.step_count;

        printf("  build %d: derive=%3u bytes/%3u steps  xor=%3u bytes/%3u steps\n",
               i, lens[i], steps_dk[i], xlen, steps_xd[i]);
    }

    printf("\n  Bytecode diff matrix (derive_key):\n");
    printf("       ");
    for (int j = 0; j < 5; j++) printf("  b%d  ", j);
    printf("\n");
    for (int i = 0; i < 5; i++) {
        printf("  b%d  ", i);
        for (int j = 0; j < 5; j++) {
            u32 cmp_len = lens[i] < lens[j] ? lens[i] : lens[j];
            int d = (i == j) ? 0 : diff_bytes(builds[i], builds[j], cmp_len);
            printf(" %3d  ", d);
        }
        printf("\n");
    }

    // Verify all 5 builds produce same key stream (functional equivalence)
    printf("\n  Functional equivalence: ");
    u8 ref_keys[35];
    {
        u8 data[128];
        memset(data, 0, sizeof(data));
        vm_state_t vm;
        vm_init(&vm, data);
        vm_shuffle_table(vm.sem_table, rt_key);
        vm.regs[0] = vm_score_encode(0, rt_key);
        __try { vm_run(&vm, builds[0], lens[0], vm_enc_key(rt_key)); } __except(1) {}
        memcpy(ref_keys, data, 35);
    }
    int all_match = 1;
    for (int i = 1; i < 5; i++) {
        u8 data[128];
        memset(data, 0, sizeof(data));
        vm_state_t vm;
        vm_init(&vm, data);
        vm_shuffle_table(vm.sem_table, rt_key);
        vm.regs[0] = vm_score_encode(0, rt_key);
        __try { vm_run(&vm, builds[i], lens[i], vm_enc_key(rt_key)); } __except(1) {}
        if (memcmp(data, ref_keys, 35) != 0) { all_match = 0; break; }
    }
    printf("%s\n\n", all_match ? "ALL 5 MATCH (different bytecode, same result)" : "MISMATCH!");

    // ================================================================
    // 2. OVERHEAD BENCHMARK — 50k iterations, percentile latency
    // ================================================================
    printf("=== Overhead Benchmark (50k iterations) ===\n");

    // Pre-build once for "static" baseline
    u8 static_prog1[1024], static_prog2[1024];
    memset(static_prog1, 0, 1024);
    memset(static_prog2, 0, 1024);
    u32 slen1 = vm_build_derive_key(static_prog1, rt_key);
    u32 slen2 = vm_build_xor_decrypt(static_prog2, rt_key);

    int N = 50000;

    // Benchmark A: run pre-built programs (interpreter only)
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < N; i++) {
        u8 work[192];
        memset(work, 0, sizeof(work));
        __try {
            vm_state_t vm;
            vm_init(&vm, work + 64);
            vm_shuffle_table(vm.sem_table, rt_key);
            vm.regs[0] = vm_score_encode(0, rt_key);
            vm_run(&vm, static_prog1, slen1, vm_enc_key(rt_key));

            for (int j = 0; j < 35; j++) work[j] = (u8)(j * 7 + 3);
            vm_state_t vm2;
            vm_init(&vm2, work);
            vm_shuffle_table(vm2.sem_table, rt_key);
            vm2.regs[0] = 35;
            vm_run(&vm2, static_prog2, slen2, vm_enc_key(rt_key));
        } __except(1) {}
    }
    QueryPerformanceCounter(&t1);
    double static_us = ((double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart / N) * 1e6;

    // Benchmark B: rebuild + run each iteration (full polymorphic)
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < N; i++) {
        u8 prog1[1024], prog2[1024];
        memset(prog1, 0, 1024);
        memset(prog2, 0, 1024);
        u32 l1 = vm_build_derive_key(prog1, rt_key);
        u32 l2 = vm_build_xor_decrypt(prog2, rt_key);

        u8 work[192];
        memset(work, 0, sizeof(work));
        __try {
            vm_state_t vm;
            vm_init(&vm, work + 64);
            vm_shuffle_table(vm.sem_table, rt_key);
            vm.regs[0] = vm_score_encode(0, rt_key);
            vm_run(&vm, prog1, l1, vm_enc_key(rt_key));

            for (int j = 0; j < 35; j++) work[j] = (u8)(j * 7 + 3);
            vm_state_t vm2;
            vm_init(&vm2, work);
            vm_shuffle_table(vm2.sem_table, rt_key);
            vm2.regs[0] = 35;
            vm_run(&vm2, prog2, l2, vm_enc_key(rt_key));
        } __except(1) {}
    }
    QueryPerformanceCounter(&t1);
    double poly_us = ((double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart / N) * 1e6;

    // Benchmark C: empty loop (baseline)
    volatile int sink = 0;
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < N; i++) {
        u8 work[192];
        memset(work, 0, sizeof(work));
        sink += work[0];
    }
    QueryPerformanceCounter(&t1);
    double base_us = ((double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart / N) * 1e6;

    printf("  Baseline (memset only):     %8.3f us\n", base_us);
    printf("  Static (pre-built + run):   %8.3f us\n", static_us);
    printf("  Poly (rebuild + run):       %8.3f us\n", poly_us);
    printf("  Build cost per call:        %8.3f us\n", poly_us - static_us);
    printf("  VM cost per call:           %8.3f us\n", static_us - base_us);
    printf("\n");
    printf("  On a 100ms program:\n");
    printf("    Static VM overhead:  +%.6f%%\n", ((static_us - base_us) / 100000.0) * 100.0);
    printf("    Poly rebuild cost:   +%.6f%%\n", ((poly_us - static_us) / 100000.0) * 100.0);
    printf("    Total overhead:      +%.6f%%\n", ((poly_us - base_us) / 100000.0) * 100.0);

    (void)sink;
    return 0;
}
