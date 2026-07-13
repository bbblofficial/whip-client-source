// ===== file: antidebug/vm/vm_dsl.h =====
//
// WhipVM bytecode DSL — write programs in expression form instead of
// hand-emitting opcodes via the raw builder.
//
// The macros wrap the canonical `vm_emit_*` builder helpers from
// vm_programs.h. They share three implicit context names declared by
// VM_PROGRAM_BEGIN:
//
//     vm_builder_t  _vm_b;     // the builder state
//     u8*           _vm_code;  // the destination buffer
//     u32           _vm_idx;   // current write index
//     u8            _vm_k;     // base key for this program
//
// Register r7 is reserved as the implicit scratch register for *_IMM
// operations (which need to load the immediate into a register before
// the actual two-register op).
//
// Anatomy of a program:
//
//     VM_PROGRAM_BEGIN(my_program, /*buf_size=*/256, /*base_key=*/0x5A)
//         VM_INPUT(r0)                  // r0 ← input
//         VM_XOR_IMM(r0, KEY_A)         // r0 ^= A
//         VM_ADD_IMM(r0, KEY_B)         // r0 += B
//         VM_MUL_IMM(r0, KEY_C)         // r0 *= C
//         VM_XOR_IMM(r0, KEY_D)         // r0 ^= D
//         VM_OUTPUT(r0)                 // result ← r0
//     VM_PROGRAM_END
//
// The block compiles into raw bytecode at the spot it was written.
// Execute the bytecode with `vm_dsl_run(my_program_code, my_program_len,
// rt_key, input)` (helper at the bottom of this file).
//
#ifndef ANTIDEBUG_VM_DSL_H
#define ANTIDEBUG_VM_DSL_H

#include "vm_interp.h"
#include "vm_programs.h"

// ---------------------------------------------------------------------------
// Register aliases — keep them as plain identifiers so the DSL reads cleanly.
// r7 is reserved by the *_IMM helpers as a scratch slot.
// ---------------------------------------------------------------------------
#define r0 0u
#define r1 1u
#define r2 2u
#define r3 3u
#define r4 4u
#define r5 5u
#define r6 6u
#define r7 7u   // reserved scratch — don't use as destination across *_IMM

// ---------------------------------------------------------------------------
// Program boilerplate
// ---------------------------------------------------------------------------
#define VM_PROGRAM_BEGIN(NAME, BUF_SIZE, BASE_KEY)                            \
    static u8  NAME##_code[BUF_SIZE];                                         \
    static u32 NAME##_len = 0u;                                               \
    static const u8 NAME##_base_key = (u8)(BASE_KEY);                         \
    static void NAME##_compile(void) {                                        \
        if (NAME##_len) return; /* idempotent */                              \
        vm_builder_t _vm_b;                                                   \
        u8*  _vm_code = NAME##_code;                                          \
        u32  _vm_idx  = 0u;                                                   \
        u8   _vm_k    = NAME##_base_key;                                      \
        vm_builder_init(&_vm_b);                                              \
        do { /* user body opens here */

// VM_PROGRAM_END takes the program name so it can write back the
// emitted length. Always terminates with HALT.
#define VM_PROGRAM_END(NAME)                                                  \
        } while (0);                                                          \
        vm_emit_halt(&_vm_b, _vm_code, &_vm_idx, _vm_k);                      \
        NAME##_len = _vm_idx;                                                 \
    }

// ---------------------------------------------------------------------------
// Loads
// ---------------------------------------------------------------------------

// Reg ← imm64
#define VM_LOAD_IMM(REG, IMM)                                                 \
    vm_emit_mov_ri(&_vm_b, _vm_code, &_vm_idx, (u8)(REG), (u64)(IMM), _vm_k)

// Reg ← byte from data_base[0]  (the input slot — wired by vm_dsl_run)
// SEM_LOAD8 reads from address held in `vm->acc`. The DSL convention:
//   acc holds the address of the input cell at program entry, and
//   vm_dsl_run sets that up before vm_run.
#define VM_INPUT(REG)                                                         \
    vm_emit_load8(&_vm_b, _vm_code, &_vm_idx, (u8)(REG), _vm_k)

// ---------------------------------------------------------------------------
// Two-register ops (REG = REG <op> SRC)
// ---------------------------------------------------------------------------
#define VM_XOR(DST, SRC)  vm_emit_rr(&_vm_b, _vm_code, &_vm_idx, SEM_XOR, (u8)(DST), (u8)(SRC), _vm_k)
#define VM_ADD(DST, SRC)  vm_emit_rr(&_vm_b, _vm_code, &_vm_idx, SEM_ADD, (u8)(DST), (u8)(SRC), _vm_k)
#define VM_MUL(DST, SRC)  vm_emit_rr(&_vm_b, _vm_code, &_vm_idx, SEM_MUL, (u8)(DST), (u8)(SRC), _vm_k)
#define VM_AND(DST, SRC)  vm_emit_rr(&_vm_b, _vm_code, &_vm_idx, SEM_AND, (u8)(DST), (u8)(SRC), _vm_k)
#define VM_CMP(DST, SRC)  vm_emit_rr(&_vm_b, _vm_code, &_vm_idx, SEM_CMP, (u8)(DST), (u8)(SRC), _vm_k)

// ---------------------------------------------------------------------------
// *_IMM helpers — load immediate into r7 scratch, then run a 2-reg op.
// ---------------------------------------------------------------------------
#define VM_XOR_IMM(DST, IMM)                                                  \
    do {                                                                      \
        VM_LOAD_IMM(r7, (IMM));                                               \
        VM_XOR((DST), r7);                                                    \
    } while (0)

#define VM_ADD_IMM(DST, IMM)                                                  \
    do {                                                                      \
        VM_LOAD_IMM(r7, (IMM));                                               \
        VM_ADD((DST), r7);                                                    \
    } while (0)

#define VM_MUL_IMM(DST, IMM)                                                  \
    do {                                                                      \
        VM_LOAD_IMM(r7, (IMM));                                               \
        VM_MUL((DST), r7);                                                    \
    } while (0)

#define VM_AND_IMM(DST, IMM)                                                  \
    do {                                                                      \
        VM_LOAD_IMM(r7, (IMM));                                               \
        VM_AND((DST), r7);                                                    \
    } while (0)

// ---------------------------------------------------------------------------
// Output — write low byte of REG to data_base[1].
// ---------------------------------------------------------------------------
#define VM_OUTPUT(REG)                                                        \
    do {                                                                      \
        VM_LOAD_IMM(r6, 1ULL);                                                \
        vm_emit_store8(&_vm_b, _vm_code, &_vm_idx, r6, (u8)(REG), _vm_k);     \
    } while (0)

// ---------------------------------------------------------------------------
// Control flow
// ---------------------------------------------------------------------------
#define VM_HALT()           vm_emit_halt(&_vm_b, _vm_code, &_vm_idx, _vm_k)
#define VM_JMP(TARGET)      vm_emit_jmp (&_vm_b, _vm_code, &_vm_idx, (u16)(TARGET), _vm_k)
#define VM_JZ(TARGET)       vm_emit_jz  (&_vm_b, _vm_code, &_vm_idx, (u16)(TARGET), _vm_k)
#define VM_JNZ(TARGET)      vm_emit_jnz (&_vm_b, _vm_code, &_vm_idx, (u16)(TARGET), _vm_k)

// ---------------------------------------------------------------------------
// Run a compiled program against a u64 input → returns the byte stored
// at data_base[1] (the VM_OUTPUT slot).
//
// The runtime key is folded to the 8-bit base key the interpreter expects.
// Pass `vm_runtime_key_stable()` for cross-thread programs, or
// `vm_runtime_key()` if the program will only run on the originating thread.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u8 vm_dsl_run(const u8* code, u32 code_len,
                               u32 rt_key, u64 input) {
    u8 data[16];
    AD_ZERO_BUF(data, sizeof(data));
    /* data[0] = input (low byte) — VM_INPUT reads from acc-pointed addr;
     * the runtime convention is acc=&data[0] at entry. We initialize acc
     * by emitting a synthetic MOV before user code if needed; here we
     * cheat and write the input low byte to data[0] for SEM_LOAD8. */
    data[0] = (u8)(input & 0xFFu);

    vm_state_t vm;
    vm_init(&vm, data);
    vm.acc = (u64)(uintptr_t)&data[0];   /* SEM_LOAD8 reads from acc */

    /* vm_run mutates `code` in place for some sema; copy to a stack-local
     * scratch so concurrent callers don't race on a shared buffer. */
    u8 scratch[1024];
    u32 i;
    u32 n = code_len < sizeof(scratch) ? code_len : (u32)sizeof(scratch);
    for (i = 0; i < n; i++) scratch[i] = code[i];

    vm_run(&vm, scratch, n, vm_enc_key(rt_key));
    return data[1];
}

#endif // ANTIDEBUG_VM_DSL_H
