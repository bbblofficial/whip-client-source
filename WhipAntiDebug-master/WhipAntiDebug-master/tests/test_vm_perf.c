#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "../antidebug/core/types.h"
#include "../antidebug/core/macros.h"
#include "../antidebug/vm/vm_interp.h"
#include "../antidebug/vm/vm_programs.h"

int main(void) {
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);

    u32 rt_key = vm_runtime_key();

    // Pre-build programs
    u8 prog1[1024], prog2[1024];
    memset(prog1, 0, sizeof(prog1));
    memset(prog2, 0, sizeof(prog2));
    u32 len1 = vm_build_derive_key(prog1, rt_key);
    u32 len2 = vm_build_xor_decrypt(prog2, rt_key);

    // Warm up
    for (int i = 0; i < 10; i++) {
        u8 work[192];
        memset(work, 0, sizeof(work));
        __try {
            vm_state_t vm;
            vm_init(&vm, work);
            vm_shuffle_table(vm.sem_table, rt_key);
            vm.regs[0] = vm_score_encode(0, rt_key);
            vm_run(&vm, prog1, len1, vm_enc_key(rt_key));
        } __except(1) {}
    }

    // Benchmark: 10000 full cycles (derive_key + xor_decrypt)
    int N = 10000;
    QueryPerformanceCounter(&t0);

    for (int i = 0; i < N; i++) {
        u8 work[192];
        memset(work, 0, sizeof(work));

        __try {
            // Phase 1: derive key
            vm_state_t vm;
            vm_init(&vm, work + 64);
            vm_shuffle_table(vm.sem_table, rt_key);
            vm.regs[0] = vm_score_encode(0, rt_key);
            vm_run(&vm, prog1, len1, vm_enc_key(rt_key));

            // Phase 2: xor decrypt
            for (int j = 0; j < 35; j++) work[j] = (u8)(j * 7 + 3);
            vm_state_t vm2;
            vm_init(&vm2, work);
            vm_shuffle_table(vm2.sem_table, rt_key);
            vm2.regs[0] = 35;
            vm_run(&vm2, prog2, len2, vm_enc_key(rt_key));
        } __except(1) {}
    }

    QueryPerformanceCounter(&t1);

    double total_s = (double)(t1.QuadPart - t0.QuadPart) / (double)freq.QuadPart;
    double per_call_us = (total_s / N) * 1e6;
    double per_call_ms = per_call_us / 1000.0;

    printf("=== VM Perf ===\n");
    printf("Iterations:    %d\n", N);
    printf("Total:         %.3f ms\n", total_s * 1000.0);
    printf("Per cycle:     %.3f us  (%.6f ms)\n", per_call_us, per_call_ms);
    printf("Overhead on 100ms program: +%.4f%%\n", (per_call_ms / 100.0) * 100.0);

    return 0;
}
