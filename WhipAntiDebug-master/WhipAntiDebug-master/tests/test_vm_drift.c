// Quick test: verify VM drift doesn't break flag decryption with score=0
#include <stdio.h>
#include <string.h>
#include "../antidebug/core/types.h"
#include "../antidebug/core/macros.h"
#include "../antidebug/vm/vm_interp.h"
#include "../antidebug/vm/vm_programs.h"

// The encrypted flag from main_example.c (score=0 key)
// We need the same encrypted blob. For testing, just verify the VM
// runs without infinite loop and produces non-zero output.

int main(void) {
    printf("[*] start\n"); fflush(stdout);
    // Test 1: VM builder + interpreter stay in sync
    printf("[*] Testing VM semantic drift sync...\n"); fflush(stdout);

    u8 code[1024];
    memset(code, 0, sizeof(code));

    printf("    calling vm_runtime_key...\n"); fflush(stdout);
    u32 rt_key = vm_runtime_key();
    printf("    runtime key = 0x%08X\n", (unsigned)rt_key); fflush(stdout);

    printf("    calling vm_build_derive_key...\n"); fflush(stdout);
    u32 prog_len = vm_build_derive_key(code, rt_key);
    printf("    derive_key program: %u bytes\n", prog_len); fflush(stdout);

    u8 data[128];
    memset(data, 0, sizeof(data));

    vm_state_t vm;
    printf("    calling vm_init...\n"); fflush(stdout);
    vm_init(&vm, data);
    vm_shuffle_table(vm.sem_table, rt_key);
    vm.regs[0] = vm_score_encode(0, rt_key);  // score = 0, cascade-encoded

    printf("    calling vm_run (derive_key)...\n"); fflush(stdout);
    __try {
        vm_run(&vm, code, prog_len, vm_enc_key(rt_key));
    } __except(1) {
        printf("    !!! EXCEPTION in vm_run at step=%u observer_shift=%u\n",
               vm.step_count, vm.observer_shift); fflush(stdout);
    }
    printf("    VM halted=%d steps=%u obs_shift=%u\n",
           vm.halted, vm.step_count, vm.observer_shift); fflush(stdout);

    // Check key stream is non-zero (means derivation worked)
    int nonzero = 0;
    for (int i = 0; i < 35; i++) {
        if (data[i] != 0) nonzero++;
    }
    printf("    key stream: %d/35 non-zero bytes\n", nonzero);

    // Test 2: XOR decrypt program
    printf("[*] Testing XOR decrypt program...\n");
    memset(code, 0, sizeof(code));
    u32 prog_len2 = vm_build_xor_decrypt(code, rt_key);
    printf("    xor_decrypt program: %u bytes\n", prog_len2);

    u8 work[192];
    memset(work, 0, sizeof(work));
    // Put dummy encrypted flag at [0..34]
    for (int i = 0; i < 35; i++) work[i] = (u8)(i * 7 + 3);
    // Put dummy key at [64..98]
    for (int i = 0; i < 35; i++) work[64 + i] = (u8)(i * 13 + 5);

    vm_state_t vm2;
    vm_init(&vm2, work);
    vm_shuffle_table(vm2.sem_table, rt_key);
    vm2.regs[0] = 35;  // flag_len

    vm_run(&vm2, code, prog_len2, vm_enc_key(rt_key));
    printf("    VM halted=%d steps=%u\n", vm2.halted, vm2.step_count);

    // Check output at [128..162] = encrypted XOR key
    int correct = 1;
    for (int i = 0; i < 35; i++) {
        u8 expected = work[i] ^ work[64 + i];
        if (work[128 + i] != expected) {
            printf("    MISMATCH at [%d]: got 0x%02X expected 0x%02X\n",
                   i, work[128 + i], expected);
            correct = 0;
        }
    }

    if (correct && nonzero > 20) {
        printf("[+] VM drift test PASSED - builder and interpreter in sync\n");
        return 0;
    } else {
        printf("[-] VM drift test FAILED!\n");
        return 1;
    }
}
