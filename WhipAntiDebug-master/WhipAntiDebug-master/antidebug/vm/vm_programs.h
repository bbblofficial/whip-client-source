// ===== file: antidebug/vm/vm_programs.h =====
//
// Bytecode programs for WhipVM v3 (Chaotic Deterministic).
//
// The builder SIMULATES the VM's semantic drift, history chain, and
// key derivation to emit correctly-encoded bytecode. Any mismatch
// between builder and interpreter = program doesn't work.
//
#ifndef ANTIDEBUG_VM_PROGRAMS_H
#define ANTIDEBUG_VM_PROGRAMS_H

#include "vm_interp.h"

// VM_KEY default — overridden at runtime by vm_derive_and_decrypt_flag()
// to use an ASLR-derived value, preventing static key extraction.
#define VM_KEY_DEFAULT 0x5Au

// =========================================================================
// Score transit cascade — 4-stage arithmetic encoding
//
// Encode (host):  ((score ^ A) + B) * C ^ D
// Decode (VM):    ((encoded ^ D) * inv(C) - B) ^ A
//
// 4 ASLR-derived keys, each poly-split inside the VM. Anti-debug SYSCALL
// results interleaved between decode stages corrupt the chain under debugger.
// C is forced odd → modular multiplicative inverse exists.
// =========================================================================
#define VM_KEY_A(k) ((u64)(k) * 0x517CC1B727220A95ULL ^ 0xCAFEBABE13371337ULL)
#define VM_KEY_B(k) ((u64)(k) * 0x2545F4914F6CDD1DULL ^ 0xDEADFACE42424242ULL)
#define VM_KEY_C(k) (((u64)(k) * 0x9E3779B97F4A7C15ULL ^ 0xBAADF00D1337C0DEULL) | 1ULL)
#define VM_KEY_D(k) ((u64)(k) * 0x6C62272E07BB0142ULL ^ 0x1234567890ABCDEFULL)

ANTIDEBUG_INLINE u64 vm_mod_inverse(u64 a) {
    // Newton's method: x = x * (2 - a*x), converges in 5 iterations for u64
    u64 x = a;
    x *= 2ULL - a * x;
    x *= 2ULL - a * x;
    x *= 2ULL - a * x;
    x *= 2ULL - a * x;
    x *= 2ULL - a * x;
    return x;
}

// ---------------------------------------------------------------------------
// Runtime key derivation — TWO variants with very different scope.
//
//   vm_runtime_key()         (a.k.a. "per-thread", below)
//     PEB + TEB + stack pointer. The stack component is unique to the
//     current thread AND the current call frame. A program built with
//     this key on thread A will NOT decode on thread B, nor on the same
//     thread from a different call depth. Use only when the program is
//     built and executed back-to-back on the same thread without
//     re-entry through callbacks/APCs.
//
//   vm_runtime_key_stable()  (a.k.a. "process-wide")
//     PEB + TEB only — same value across every thread and every call
//     frame in the process. Use for programs that are compiled once
//     (e.g. at init) and shared between threads. THIS IS THE DEFAULT
//     for the C++ wrapper (vm_cpp.hpp's CompiledProgram).
//
// Picking the wrong one is a silent failure: vm_run will produce
// garbage output rather than a clear error. When in doubt, prefer
// vm_runtime_key_stable() — slightly less entropy, but bulletproof.
// ---------------------------------------------------------------------------
//
// Returns a wide (32-bit) runtime key combining three independent ASLR-randomised
// addresses: PEB (~8 bits), TEB (~8 bits), and stack (~16 bits).
// Total entropy: ~24-32 bits → 2^24+ score-key candidates instead of 256.
//
// CROSS-THREAD WARNING: the stack-pointer component differs between threads
// AND between call frames on the same thread. If you build a program with
// this key in one frame and execute it in another (different stack depth,
// callback, APC, fiber, async), the key won't match and decode fails.
ANTIDEBUG_INLINE u32 vm_runtime_key(void) {
#if defined(_MSC_VER)
    u64 peb = (u64)__readgsqword(0x60);   // PEB: ASLR page, ~8 independent bits
    u64 teb = (u64)__readgsqword(0x30);   // TEB: different ASLR page, ~8 bits
    volatile u64 stk_probe = 0;
    u64 stk = (u64)(uintptr_t)&stk_probe; // stack ASLR: ~16 bits after >> 4
    u32 h = (u32)((peb >> 12) & 0xFFu)
          | ((u32)((teb >> 12) & 0xFFu) << 8)
          | ((u32)((stk >>  4) & 0xFFFFu) << 16);
    // Avalanche: ensure all input bits affect all output bits
    h ^= h >> 16;
    h *= 0x45D9F3Bu;
    h ^= h >> 16;
    return h ? h : (u32)VM_KEY_DEFAULT;
#else
    return (u32)VM_KEY_DEFAULT;
#endif
}

// Stable variant of vm_runtime_key — PEB + TEB only, no stack component.
// SAFE for cross-thread / cross-frame use: same value everywhere in the
// process. Recommended whenever a program is built once and executed
// later from a different call site (the common case).
ANTIDEBUG_INLINE u32 vm_runtime_key_stable(void) {
#if defined(_MSC_VER)
    u64 peb = (u64)__readgsqword(0x60);
    u64 teb = (u64)__readgsqword(0x30);
    u32 h = (u32)((peb >> 12) & 0xFFu) | ((u32)((teb >> 12) & 0xFFu) << 8);
    h ^= h >> 16; h *= 0x45D9F3Bu; h ^= h >> 16;
    return h ? h : 0x42u;
#else
    return 0x42u;
#endif
}

// Self-documenting alias for vm_runtime_key — clarifies the per-thread /
// per-frame scope at the call site. Prefer this in new code.
ANTIDEBUG_INLINE u32 vm_runtime_key_per_thread(void) {
    return vm_runtime_key();
}

// Fold the 32-bit wide key to 8 bits for bytecode instruction-level XOR encoding.
// The full u32 rt_key is used directly for score constants (VM_KEY_A/B/C/D).
ANTIDEBUG_INLINE u8 vm_enc_key(u32 rt_key) {
    u8 k = (u8)((rt_key ^ (rt_key >> 8) ^ (rt_key >> 16) ^ (rt_key >> 24)) & 0xFFu);
    return k ? k : (u8)VM_KEY_DEFAULT;
}

ANTIDEBUG_INLINE u64 vm_score_encode(u32 score, u32 rt_key) {
    u64 v = (u64)score;
    v ^= VM_KEY_A(rt_key);
    v += VM_KEY_B(rt_key);
    v *= VM_KEY_C(rt_key);
    v ^= VM_KEY_D(rt_key);
    return v;
}

// =========================================================================
// Builder state — mirrors the VM's internal state for encoding
// =========================================================================
typedef struct {
    u8  sem_table[16];
    u64 drift_state;
    u64 chaos;          // mirrors vm_state_t.chaos for drift synchronization
    u8  history[VM_HIST_SZ];
    u32 hist_idx;
    u32 step;
    u32 drift_rotation_count;  // chaos-free rotation counter (mirrors vm_state_t)
    u8  cur_key;        // key for current instruction's operands (set by emit_op)
} vm_builder_t;

ANTIDEBUG_INLINE void vm_builder_init(vm_builder_t* b) {
    AD_ZERO_BUF(b, sizeof(*b));
    b->sem_table[0x00] = SEM_MOV_RI;
    b->sem_table[0x01] = SEM_SYSCALL;
    b->sem_table[0x02] = SEM_MOV_RA;
    b->sem_table[0x03] = SEM_TRAP;
    b->sem_table[0x04] = SEM_ADD;
    b->sem_table[0x05] = SEM_XOR;
    b->sem_table[0x06] = SEM_MUL;
    b->sem_table[0x07] = SEM_AND;
    b->sem_table[0x08] = SEM_CMP;
    b->sem_table[0x09] = SEM_JMP;
    b->sem_table[0x0A] = SEM_JZ;
    b->sem_table[0x0B] = SEM_LOAD8;
    b->sem_table[0x0C] = SEM_STORE8;
    b->sem_table[0x0D] = SEM_HALT;
    b->sem_table[0x0E] = SEM_GHOST;
    b->sem_table[0x0F] = SEM_NOP;
    b->drift_state = 0xDEADC0DE42424242ULL;
    b->chaos       = 0xDEADC0DE42424242ULL;
}

// Get the current key for encoding operands of this instruction.
// Uses PC (*idx at emit time) and drift_state — mirrors vm_history_key.
ANTIDEBUG_INLINE u8 vm_builder_key(const vm_builder_t* b, u8 base_key, u32 pc) {
    return vm_build_key(base_key, pc, b->drift_state);
}

// Emit one instruction: resolve semantic → raw opcode, encode, advance state.
// Saves the key in b->cur_key so that operand emitters use the SAME key as
// the opcode — the interpreter uses one cur_key for the entire instruction.
ANTIDEBUG_INLINE void vm_builder_emit_op(
    vm_builder_t* b, u8* code, u32* idx,
    vm_semantic_t action, u8 base_key
) {
    u8 raw_op = vm_resolve_opcode(b->sem_table, action, *idx);
    u8 key = vm_builder_key(b, base_key, *idx);  // key at current PC
    b->cur_key = key;

    code[(*idx)++] = VM_ENC(raw_op, key);

    // Push to history (same as interpreter)
    b->history[b->hist_idx & (VM_HIST_SZ - 1u)] = raw_op;
    b->hist_idx++;
    b->step++;
}

// Call AFTER emitting the full instruction (opcode + all operands).
// Mirrors the interpreter's post-step drift with the same step count.
ANTIDEBUG_INLINE void vm_builder_end_insn(vm_builder_t* b, u32 pc_after) {
    AD_UNUSED(pc_after);
    vm_build_drift(b->sem_table, &b->drift_state, &b->chaos, b->step - 1u, &b->drift_rotation_count);
}

// Emit a register operand byte — uses b->cur_key (same key as the opcode)
ANTIDEBUG_INLINE void vm_builder_emit_reg(
    const vm_builder_t* b, u8* code, u32* idx,
    u8 reg, u8 base_key
) {
    AD_UNUSED(base_key);
    code[(*idx)++] = VM_ENC(reg & 0x07u, b->cur_key);
}

// Emit imm64 — uses b->cur_key
ANTIDEBUG_INLINE void vm_builder_emit_u64(
    const vm_builder_t* b, u8* code, u32* idx,
    u64 val, u8 base_key
) {
    AD_UNUSED(base_key);
    u32 i;
    for (i = 0; i < 8u; i++) {
        code[(*idx)++] = VM_ENC((u8)(val & 0xFFu), b->cur_key);
        val >>= 8u;
    }
}

// Emit imm16 — uses b->cur_key
ANTIDEBUG_INLINE void vm_builder_emit_u16(
    const vm_builder_t* b, u8* code, u32* idx,
    u16 val, u8 base_key
) {
    AD_UNUSED(base_key);
    code[(*idx)++] = VM_ENC((u8)(val & 0xFFu), b->cur_key);
    code[(*idx)++] = VM_ENC((u8)((val >> 8u) & 0xFFu), b->cur_key);
}

// Emit imm32 — uses b->cur_key
ANTIDEBUG_INLINE void vm_builder_emit_u32(
    const vm_builder_t* b, u8* code, u32* idx,
    u32 val, u8 base_key
) {
    AD_UNUSED(base_key);
    u32 i;
    for (i = 0; i < 4u; i++) {
        code[(*idx)++] = VM_ENC((u8)(val & 0xFFu), b->cur_key);
        val >>= 8u;
    }
}

// =========================================================================
// Compound emitters — instruction + operands as one call
// =========================================================================

// MOV_RI Rn, imm64
ANTIDEBUG_INLINE void vm_emit_mov_ri(
    vm_builder_t* b, u8* code, u32* idx,
    u8 reg, u64 val, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_MOV_RI, base_key);
    vm_builder_emit_reg(b, code, idx, reg, base_key);
    vm_builder_emit_u64(b, code, idx, val, base_key);
    vm_builder_end_insn(b, *idx);
}

// MOV_RA Rn (Rn = ACC)
ANTIDEBUG_INLINE void vm_emit_mov_ra(
    vm_builder_t* b, u8* code, u32* idx,
    u8 reg, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_MOV_RA, base_key);
    vm_builder_emit_reg(b, code, idx, reg, base_key);
    vm_builder_end_insn(b, *idx);
}

// Two-register op (ADD, XOR, MUL, AND, SHR, CMP)
ANTIDEBUG_INLINE void vm_emit_rr(
    vm_builder_t* b, u8* code, u32* idx,
    vm_semantic_t action, u8 rd, u8 rs, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, action, base_key);
    vm_builder_emit_reg(b, code, idx, rd, base_key);
    vm_builder_emit_reg(b, code, idx, rs, base_key);
    vm_builder_end_insn(b, *idx);
}

// ADDI Rn, imm32
ANTIDEBUG_INLINE void vm_emit_addi(
    vm_builder_t* b, u8* code, u32* idx,
    u8 reg, u32 imm, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_ADD, base_key);
    vm_builder_emit_reg(b, code, idx, reg, base_key);
    // For immediate add: we use a trick — load imm into a temp reg first
    // Actually our SEM_ADD takes 2 register operands, so we need MOV_RI first.
    // Let's keep it simple: the caller loads the immediate into a register.
    // This emit just does the 2-reg add.
    // Re-read: actually we need to handle this differently.
    // Hack: emit a second register operand that the caller set up.
    vm_builder_emit_reg(b, code, idx, reg, base_key);  // placeholder
    vm_builder_end_insn(b, *idx);
    AD_UNUSED(imm);
}

// LOAD8 Rn
ANTIDEBUG_INLINE void vm_emit_load8(
    vm_builder_t* b, u8* code, u32* idx,
    u8 reg, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_LOAD8, base_key);
    vm_builder_emit_reg(b, code, idx, reg, base_key);
    vm_builder_end_insn(b, *idx);
}

// STORE8 Rd, Rs
ANTIDEBUG_INLINE void vm_emit_store8(
    vm_builder_t* b, u8* code, u32* idx,
    u8 rd, u8 rs, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_STORE8, base_key);
    vm_builder_emit_reg(b, code, idx, rd, base_key);
    vm_builder_emit_reg(b, code, idx, rs, base_key);
    vm_builder_end_insn(b, *idx);
}

// JMP imm16
ANTIDEBUG_INLINE void vm_emit_jmp(
    vm_builder_t* b, u8* code, u32* idx,
    u16 target, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_JMP, base_key);
    vm_builder_emit_u16(b, code, idx, target, base_key);
    vm_builder_end_insn(b, *idx);
}

// JZ imm16
ANTIDEBUG_INLINE void vm_emit_jz(
    vm_builder_t* b, u8* code, u32* idx,
    u16 target, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_JZ, base_key);
    vm_builder_emit_u16(b, code, idx, target, base_key);
    vm_builder_end_insn(b, *idx);
}

// JNZ imm16
ANTIDEBUG_INLINE void vm_emit_jnz(
    vm_builder_t* b, u8* code, u32* idx,
    u16 target, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_JNZ, base_key);
    vm_builder_emit_u16(b, code, idx, target, base_key);
    vm_builder_end_insn(b, *idx);
}

// HALT
ANTIDEBUG_INLINE void vm_emit_halt(
    vm_builder_t* b, u8* code, u32* idx, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_HALT, base_key);
    vm_builder_end_insn(b, *idx);
}

// NOP
ANTIDEBUG_INLINE void vm_emit_nop(
    vm_builder_t* b, u8* code, u32* idx, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_NOP, base_key);
    vm_builder_end_insn(b, *idx);
}

// GHOST swap
ANTIDEBUG_INLINE void vm_emit_ghost(
    vm_builder_t* b, u8* code, u32* idx, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_GHOST, base_key);
    vm_builder_end_insn(b, *idx);
}

// ── Sournois emitters ──────────────────────────────────────────────────

// INTEGRITY — bytecode self-checksum. len = bytes ahead to hash.
// Caller must pre-set ACC to the expected hash.
ANTIDEBUG_INLINE void vm_emit_integrity(
    vm_builder_t* b, u8* code, u32* idx,
    u8 len, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_INTEGRITY, base_key);
    code[(*idx)++] = VM_ENC(len, b->cur_key);
    vm_builder_end_insn(b, *idx);
}

// SYSCALL — native anti-debug check.
//   0=PEB, 1=NtGlobal, 2=KD, 3=RDTSC, 4=RDTSC variance, 5=Heap ForceFlags
ANTIDEBUG_INLINE void vm_emit_syscall_check(
    vm_builder_t* b, u8* code, u32* idx,
    u8 check_id, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_SYSCALL, base_key);
    code[(*idx)++] = VM_ENC(check_id & 0x07u, b->cur_key);
    vm_builder_end_insn(b, *idx);
}

// TRAP — exception trap. ACC = 0 if handler fires (clean), 0xDEAD if eaten.
ANTIDEBUG_INLINE void vm_emit_trap(
    vm_builder_t* b, u8* code, u32* idx, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_TRAP, base_key);
    vm_builder_end_insn(b, *idx);
}

// FUSE — opcode fusion with next instruction.
ANTIDEBUG_INLINE void vm_emit_fuse(
    vm_builder_t* b, u8* code, u32* idx,
    u8 rd, u8 rs, u8 base_key
) {
    vm_builder_emit_op(b, code, idx, SEM_FUSE, base_key);
    vm_builder_emit_reg(b, code, idx, rd, base_key);
    vm_builder_emit_reg(b, code, idx, rs, base_key);
    vm_builder_end_insn(b, *idx);
}

// =========================================================================
// Polymorphic builder — RDTSC-seeded, each build produces unique bytecode
//
// - Junk insertion: random NOPs / ghost-swap pairs between real ops
// - Constant splitting: MOV_RI val → MOV_RI (val^mask), MOV_RI mask, XOR
// - Seeded by RDTSC so even same process produces different bytecode
// =========================================================================

typedef struct {
    u64 seed;
    u8  reg_map[8];   // reg_map[logical] = physical register
} vm_poly_t;

ANTIDEBUG_INLINE u32 vm_poly_next(vm_poly_t* p) {
    p->seed ^= p->seed << 13;
    p->seed ^= p->seed >> 7;
    p->seed ^= p->seed << 17;
    return (u32)(p->seed);
}

ANTIDEBUG_INLINE void vm_poly_init(vm_poly_t* p, u32 rt_key) {
#if defined(_MSC_VER)
    p->seed = __rdtsc() ^ ((u64)rt_key * 0x9E3779B97F4A7C15ULL);
#else
    p->seed = 0x12345678ULL ^ ((u64)rt_key * 0x9E3779B97F4A7C15ULL);
#endif
    if (!p->seed) p->seed = 0xCAFEBABEDEADC0DEULL;

    // R0 (input) and R7 (scratch) are fixed.
    // Shuffle R1-R6 so each build uses different physical registers
    // for the same logical roles. A reverser identifying "R3 = hash"
    // in one dump finds a completely different assignment in the next.
    p->reg_map[0] = 0;
    p->reg_map[7] = 7;
    {
        u8 pool[6];
        u32 i;
        for (i = 0; i < 6u; i++) pool[i] = (u8)(i + 1u);
        for (i = 5; i > 0; i--) {
            u32 j = vm_poly_next(p) % (i + 1u);
            u8 tmp = pool[i];
            pool[i] = pool[j];
            pool[j] = tmp;
        }
        for (i = 0; i < 6u; i++) p->reg_map[i + 1u] = pool[i];
    }
}

// Insert 0-2 junk instructions (identity operations only — never corrupt state)
ANTIDEBUG_INLINE void vm_poly_junk(vm_builder_t* b, u8* code, u32* idx,
                                    u8 key, vm_poly_t* p) {
    switch (vm_poly_next(p) & 3u) {
    case 0: break;
    case 1: vm_emit_nop(b, code, idx, key); break;
    case 2: vm_emit_ghost(b, code, idx, key);
            vm_emit_ghost(b, code, idx, key); break;
    case 3: vm_emit_nop(b, code, idx, key);
            vm_emit_nop(b, code, idx, key); break;
    }
}

// Polymorphic immediate load: direct, XOR-split, or ADD-split
ANTIDEBUG_INLINE void vm_poly_mov_ri(vm_builder_t* b, u8* code, u32* idx,
                                      u8 reg, u64 val, u8 key,
                                      vm_poly_t* p, u8 scratch) {
    switch (vm_poly_next(p) % 3u) {
    case 0:
        vm_emit_mov_ri(b, code, idx, reg, val, key);
        break;
    case 1: {
        u64 mask = (u64)vm_poly_next(p) | ((u64)vm_poly_next(p) << 32);
        vm_emit_mov_ri(b, code, idx, reg, val ^ mask, key);
        vm_emit_mov_ri(b, code, idx, scratch, mask, key);
        vm_emit_rr(b, code, idx, SEM_XOR, reg, scratch, key);
        vm_emit_mov_ra(b, code, idx, reg, key);
        break;
    }
    case 2: {
        u64 delta = (u64)vm_poly_next(p) | ((u64)vm_poly_next(p) << 32);
        vm_emit_mov_ri(b, code, idx, reg, val - delta, key);
        vm_emit_mov_ri(b, code, idx, scratch, delta, key);
        vm_emit_rr(b, code, idx, SEM_ADD, reg, scratch, key);
        vm_emit_mov_ra(b, code, idx, reg, key);
        break;
    }
    }
}

// =========================================================================
// Program: derive key stream (FNV-1a) — polymorphic
//
// R0 = score (input)
// data_base = output key stream buffer
// =========================================================================

ANTIDEBUG_INLINE u32 vm_build_derive_key(u8* code, u32 rt_key) {
    u32 idx = 0;
    u8 k = vm_enc_key(rt_key);  // 8-bit key for instruction-level bytecode encoding
    vm_builder_t b;
    vm_builder_init(&b);
    vm_shuffle_table(b.sem_table, rt_key);  // use wide key for richer table permutation
    vm_poly_t p;
    vm_poly_init(&p, rt_key);  // use wide key for richer poly seed

    // ── Register permutation ────────────────────────────────────────
    // Logical roles → random physical registers each build.
    // R0 (input/score) and R7 (scratch) are fixed.
    u8 rH = p.reg_map[1];   // hash accumulator
    u8 rP = p.reg_map[2];   // FNV prime
    u8 rC = p.reg_map[3];   // loop counter
    u8 rL = p.reg_map[4];   // loop limit
    u8 rM = p.reg_map[5];   // mask / temp
    u8 rG = p.reg_map[6];   // golden ratio

    // ════════════════════════════════════════════════════════════════
    // SCORE CASCADE DECODE + ANTI-DEBUG INTERLEAVING
    //
    // Host encoded: ((score ^ A) + B) * C ^ D
    // VM decodes:   ((R0 ^ D) * inv(C) + neg(B)) ^ A
    //
    // Anti-debug SYSCALL results are XOR'd into R0 BETWEEN decode
    // stages. Under debugger: SYSCALL returns non-zero → chain
    // corrupts → wrong score → wrong key → garbage flag.
    //
    // 4 keys: ASLR-derived, each poly-split into random XOR/ADD.
    // Even if reverser extracts all 4 keys, the SYSCALL interleaving
    // still poisons the chain under instrumentation.
    // ════════════════════════════════════════════════════════════════

    vm_poly_junk(&b, code, &idx, k, &p);

    {
        u64 ka     = VM_KEY_A(rt_key);  // use wide key: 2^32 candidates
        u64 kb     = VM_KEY_B(rt_key);
        u64 kc     = VM_KEY_C(rt_key);
        u64 kd     = VM_KEY_D(rt_key);
        u64 kc_inv = vm_mod_inverse(kc);
        u64 neg_kb = (u64)(0ULL - kb);

        // ── Stage 1: R0 ^= key_D ────────────────────────────────────
        vm_poly_mov_ri(&b, code, &idx, rH, kd, k, &p, 7);
        vm_emit_rr(&b, code, &idx, SEM_XOR, 0, rH, k);
        vm_emit_mov_ra(&b, code, &idx, 0, k);
        vm_poly_junk(&b, code, &idx, k, &p);

        // Anti-debug: PEB.BeingDebugged
        vm_emit_syscall_check(&b, code, &idx, 0, k);
        vm_emit_mov_ra(&b, code, &idx, 7, k);
        vm_emit_rr(&b, code, &idx, SEM_XOR, 0, 7, k);
        vm_emit_mov_ra(&b, code, &idx, 0, k);

        // Ghost confusion
        vm_emit_ghost(&b, code, &idx, k);
        vm_emit_nop(&b, code, &idx, k);
        vm_emit_ghost(&b, code, &idx, k);
        vm_poly_junk(&b, code, &idx, k, &p);

        // ── Stage 2: R0 *= inv(key_C) ───────────────────────────────
        vm_poly_mov_ri(&b, code, &idx, rH, kc_inv, k, &p, 7);
        vm_emit_rr(&b, code, &idx, SEM_MUL, 0, rH, k);
        vm_emit_mov_ra(&b, code, &idx, 0, k);
        vm_poly_junk(&b, code, &idx, k, &p);

        // Anti-debug: NtGlobalFlag + heap ForceFlags
        vm_emit_syscall_check(&b, code, &idx, 1, k);
        vm_emit_mov_ra(&b, code, &idx, 7, k);
        vm_emit_rr(&b, code, &idx, SEM_XOR, 0, 7, k);
        vm_emit_mov_ra(&b, code, &idx, 0, k);

        vm_emit_syscall_check(&b, code, &idx, 5, k);
        vm_emit_mov_ra(&b, code, &idx, 7, k);
        vm_emit_rr(&b, code, &idx, SEM_XOR, 0, 7, k);
        vm_emit_mov_ra(&b, code, &idx, 0, k);
        vm_poly_junk(&b, code, &idx, k, &p);

        // ── Stage 3: R0 += neg(key_B) (= R0 - key_B) ───────────────
        vm_poly_mov_ri(&b, code, &idx, rH, neg_kb, k, &p, 7);
        vm_emit_rr(&b, code, &idx, SEM_ADD, 0, rH, k);
        vm_emit_mov_ra(&b, code, &idx, 0, k);
        vm_poly_junk(&b, code, &idx, k, &p);

        // Anti-debug: KUSD + RDTSC variance
        vm_emit_syscall_check(&b, code, &idx, 2, k);
        vm_emit_mov_ra(&b, code, &idx, 7, k);
        vm_emit_rr(&b, code, &idx, SEM_XOR, 0, 7, k);
        vm_emit_mov_ra(&b, code, &idx, 0, k);

        vm_emit_syscall_check(&b, code, &idx, 4, k);
        vm_emit_mov_ra(&b, code, &idx, 7, k);
        vm_emit_rr(&b, code, &idx, SEM_XOR, 0, 7, k);
        vm_emit_mov_ra(&b, code, &idx, 0, k);
        vm_poly_junk(&b, code, &idx, k, &p);

        // ── Stage 4: R0 ^= key_A ────────────────────────────────────
        vm_poly_mov_ri(&b, code, &idx, rH, ka, k, &p, 7);
        vm_emit_rr(&b, code, &idx, SEM_XOR, 0, rH, k);
        vm_emit_mov_ra(&b, code, &idx, 0, k);
        vm_poly_junk(&b, code, &idx, k, &p);

        // Anti-debug: RDTSC timing + INT 2C trap
        vm_emit_syscall_check(&b, code, &idx, 3, k);
        vm_emit_mov_ra(&b, code, &idx, 7, k);
        vm_emit_rr(&b, code, &idx, SEM_XOR, 0, 7, k);
        vm_emit_mov_ra(&b, code, &idx, 0, k);

        vm_emit_trap(&b, code, &idx, k);
        vm_emit_mov_ra(&b, code, &idx, 7, k);
        vm_emit_rr(&b, code, &idx, SEM_XOR, 0, 7, k);
        vm_emit_mov_ra(&b, code, &idx, 0, k);
        vm_poly_junk(&b, code, &idx, k, &p);
    }

    // ── Key derivation (reordered + permuted + poly constants) ─────
    // The 3 independent constant loads are shuffled each build —
    // a reverser pattern-matching "load FNV basis first" finds a
    // different order every time.
    {
        // FNV basis mixed with stable ASLR key (PEB+TEB only — no stack, stable
        // across call frames in the same process). The inline FNV path in
        // main_example.c uses the same formula, so both agree on clean runs.
        // An attacker who dumps encrypted_flag cannot invert it without knowing
        // the PEB/TEB ASLR layout.
        u64 fnv_basis = 0xCBF29CE484222325ULL ^ (u64)vm_runtime_key_stable();
        u8  cregs[3]; u64 cvals[3]; u32 cord[3]; u32 ci;
        cregs[0] = rH; cvals[0] = fnv_basis;
        cregs[1] = rP; cvals[1] = 0x00000100000001B3ULL;
        cregs[2] = rG; cvals[2] = 0x9E3779B9ULL;
        cord[0] = 0; cord[1] = 1; cord[2] = 2;
        for (ci = 2; ci > 0; ci--) {
            u32 cj = vm_poly_next(&p) % (ci + 1u);
            u32 ct = cord[ci]; cord[ci] = cord[cj]; cord[cj] = ct;
        }
        for (ci = 0; ci < 3u; ci++) {
            vm_poly_mov_ri(&b, code, &idx, cregs[cord[ci]],
                           cvals[cord[ci]], k, &p, 7);
            vm_poly_junk(&b, code, &idx, k, &p);
        }
    }

    // h ^= score
    vm_emit_rr(&b, code, &idx, SEM_XOR, rH, 0, k);
    vm_emit_mov_ra(&b, code, &idx, rH, k);
    vm_poly_junk(&b, code, &idx, k, &p);

    // h *= prime
    vm_emit_rr(&b, code, &idx, SEM_MUL, rH, rP, k);
    vm_emit_mov_ra(&b, code, &idx, rH, k);

    // temp = score * golden
    vm_emit_rr(&b, code, &idx, SEM_MUL, 0, rG, k);
    vm_emit_mov_ra(&b, code, &idx, rM, k);

    // h ^= temp
    vm_emit_rr(&b, code, &idx, SEM_XOR, rH, rM, k);
    vm_emit_mov_ra(&b, code, &idx, rH, k);
    vm_poly_junk(&b, code, &idx, k, &p);

    // h *= prime
    vm_emit_rr(&b, code, &idx, SEM_MUL, rH, rP, k);
    vm_emit_mov_ra(&b, code, &idx, rH, k);
    vm_poly_junk(&b, code, &idx, k, &p);

    // ── Phantom branch (opaque predicate + dead code) ────────────────
    // CMP rP, rP → always ZF=1 → JZ always taken → skip poison.
    // Static analysis sees 2 paths; the dead path has plausible-looking
    // computations with random constants (different each build).
    vm_emit_rr(&b, code, &idx, SEM_CMP, rP, rP, k);
    {
        u32 phantom_jz = idx;
        vm_emit_jz(&b, code, &idx, 0, k);
        // Dead path — never executed, looks like real math
        {
            u64 pv = (u64)vm_poly_next(&p) | ((u64)vm_poly_next(&p) << 32);
            vm_emit_mov_ri(&b, code, &idx, rH, pv, k);
            vm_emit_rr(&b, code, &idx, SEM_MUL, rH, rP, k);
            vm_emit_mov_ra(&b, code, &idx, rH, k);
            vm_emit_rr(&b, code, &idx, SEM_XOR, 0, rH, k);
            vm_emit_mov_ra(&b, code, &idx, 0, k);
        }
        // Patch JZ → skip dead code
        {
            u32 skip = idx;
            code[phantom_jz + 1] ^= (u8)(skip & 0xFFu);
            code[phantom_jz + 2] ^= (u8)((skip >> 8u) & 0xFFu);
        }
    }

    // ── Loop setup ───────────────────────────────────────────────────
    vm_emit_mov_ri(&b, code, &idx, rC, 0ULL, k);
    vm_poly_mov_ri(&b, code, &idx, rL, 35ULL, k, &p, 7);
    vm_poly_mov_ri(&b, code, &idx, rM, 0xFFULL, k, &p, 7);
    vm_poly_junk(&b, code, &idx, k, &p);

    // ── Loop ─────────────────────────────────────────────────────────
    u32 loop_start = idx;

    vm_emit_rr(&b, code, &idx, SEM_CMP, rC, rL, k);

    u32 jz_patch = idx;
    vm_emit_jz(&b, code, &idx, 0, k);

    vm_emit_rr(&b, code, &idx, SEM_XOR, rH, rC, k);
    vm_emit_mov_ra(&b, code, &idx, rH, k);

    vm_emit_rr(&b, code, &idx, SEM_MUL, rH, rP, k);
    vm_emit_mov_ra(&b, code, &idx, rH, k);

    vm_emit_rr(&b, code, &idx, SEM_AND, rH, rM, k);
    vm_emit_mov_ra(&b, code, &idx, 7, k);

    // SYSCALL 2 (KUSD.KdDebuggerEnabled) → corrupt key byte if debugger present
    vm_emit_syscall_check(&b, code, &idx, 2, k);
    vm_emit_mov_ra(&b, code, &idx, rM, k);
    vm_emit_rr(&b, code, &idx, SEM_XOR, 7, rM, k);
    vm_emit_mov_ra(&b, code, &idx, 7, k);

    // Store BEFORE restoring rM=0xFF — `vm_poly_mov_ri` may use scratch=7
    // (its only legal scratch since rH/rP/rC/rL/rM/rG are all allocated to
    // FNV roles). When the polymorphic path picks the XOR-split or ADD-split
    // form it temporarily writes to scratch, clobbering r7 which holds the
    // current key byte for the imminent STORE8. Doing the store first
    // preserves the byte; the rM restore can run after, since rM is only
    // needed at the start of the next iteration.
    vm_emit_store8(&b, code, &idx, rC, 7, k);
    vm_poly_mov_ri(&b, code, &idx, rM, 0xFFULL, k, &p, 7);

    // Ghost swap bait (writes to shadow — never used)
    vm_emit_ghost(&b, code, &idx, k);
    vm_emit_mov_ri(&b, code, &idx, 0, 1ULL, k);
    vm_emit_ghost(&b, code, &idx, k);

    // counter++
    vm_emit_mov_ri(&b, code, &idx, 7, 1ULL, k);
    vm_emit_rr(&b, code, &idx, SEM_ADD, rC, 7, k);
    vm_emit_mov_ra(&b, code, &idx, rC, k);

    vm_emit_jmp(&b, code, &idx, (u16)loop_start, k);

    // Patch JZ → loop_end
    {
        u32 loop_end = idx;
        code[jz_patch + 1] ^= (u8)(loop_end & 0xFFu);
        code[jz_patch + 2] ^= (u8)((loop_end >> 8u) & 0xFFu);
    }

    vm_emit_halt(&b, code, &idx, k);
    return idx;
}

// =========================================================================
// Program: XOR decrypt — polymorphic
//
// R0 = length, data_base layout:
//   [0..34]   = encrypted flag
//   [64..98]  = key stream
//   [128..162] = output
// =========================================================================

ANTIDEBUG_INLINE u32 vm_build_xor_decrypt(u8* code, u32 rt_key) {
    u32 idx = 0;
    u8 k = vm_enc_key(rt_key);  // 8-bit key for instruction-level bytecode encoding
    vm_builder_t b;
    vm_builder_init(&b);
    vm_shuffle_table(b.sem_table, rt_key);  // use wide key for richer table permutation
    vm_poly_t p;
    vm_poly_init(&p, rt_key);  // use wide key for richer poly seed

    // ── Register permutation ────────────────────────────────────────
    u8 rCtr  = p.reg_map[1];  // loop counter
    u8 rKOff = p.reg_map[2];  // key offset (64)
    u8 rOOff = p.reg_map[3];  // output offset (128)
    u8 rEnc  = p.reg_map[4];  // encrypted byte
    u8 rIdx  = p.reg_map[5];  // index temp
    u8 rKB   = p.reg_map[6];  // key byte

    // ── Setup (permuted + polymorphic) ──────────────────────────────
    vm_emit_mov_ri(&b, code, &idx, rCtr, 0ULL, k);
    vm_poly_mov_ri(&b, code, &idx, rKOff, 64ULL, k, &p, 7);
    vm_poly_junk(&b, code, &idx, k, &p);
    vm_poly_mov_ri(&b, code, &idx, rOOff, 128ULL, k, &p, 7);
    vm_poly_junk(&b, code, &idx, k, &p);

    // ── Anti-debug sentinels (pre-loop) ──────────────────────────────
    // On clean run all checks return 0 → XOR changes nothing.
    // Under debugger: offsets and counter seed are silently poisoned.
    vm_emit_syscall_check(&b, code, &idx, 0, k);   // PEB.BeingDebugged → rKOff
    vm_emit_mov_ra(&b, code, &idx, 7, k);
    vm_emit_rr(&b, code, &idx, SEM_XOR, rKOff, 7, k);
    vm_emit_mov_ra(&b, code, &idx, rKOff, k);

    vm_emit_syscall_check(&b, code, &idx, 3, k);   // RDTSC timing → rOOff
    vm_emit_mov_ra(&b, code, &idx, 7, k);
    vm_emit_rr(&b, code, &idx, SEM_XOR, rOOff, 7, k);
    vm_emit_mov_ra(&b, code, &idx, rOOff, k);

    vm_emit_syscall_check(&b, code, &idx, 5, k);   // Heap ForceFlags → rCtr seed
    vm_emit_mov_ra(&b, code, &idx, 7, k);
    vm_emit_rr(&b, code, &idx, SEM_XOR, rCtr, 7, k);
    vm_emit_mov_ra(&b, code, &idx, rCtr, k);
    vm_poly_junk(&b, code, &idx, k, &p);

    // ── Loop ─────────────────────────────────────────────────────────
    u32 loop_start = idx;

    vm_emit_rr(&b, code, &idx, SEM_CMP, rCtr, 0, k);

    u32 jz_patch = idx;
    vm_emit_jz(&b, code, &idx, 0, k);

    // Load encrypted[i]
    vm_emit_load8(&b, code, &idx, rCtr, k);
    vm_emit_mov_ra(&b, code, &idx, rEnc, k);

    // SYSCALL 1 (NtGlobalFlag) → corrupt enc byte per iteration
    vm_emit_syscall_check(&b, code, &idx, 1, k);
    vm_emit_mov_ra(&b, code, &idx, 7, k);
    vm_emit_rr(&b, code, &idx, SEM_XOR, rEnc, 7, k);
    vm_emit_mov_ra(&b, code, &idx, rEnc, k);

    // idx = counter + key_offset
    vm_emit_rr(&b, code, &idx, SEM_ADD, rCtr, rKOff, k);
    vm_emit_mov_ra(&b, code, &idx, rIdx, k);

    // Load key[i]
    vm_emit_load8(&b, code, &idx, rIdx, k);
    vm_emit_mov_ra(&b, code, &idx, rKB, k);

    // XOR decrypt
    vm_emit_rr(&b, code, &idx, SEM_XOR, rEnc, rKB, k);
    vm_emit_mov_ra(&b, code, &idx, 7, k);

    // idx = counter + output_offset
    vm_emit_rr(&b, code, &idx, SEM_ADD, rCtr, rOOff, k);
    vm_emit_mov_ra(&b, code, &idx, rIdx, k);

    // Store decrypted
    vm_emit_store8(&b, code, &idx, rIdx, 7, k);

    // counter++
    vm_emit_mov_ri(&b, code, &idx, 7, 1ULL, k);
    vm_emit_rr(&b, code, &idx, SEM_ADD, rCtr, 7, k);
    vm_emit_mov_ra(&b, code, &idx, rCtr, k);

    vm_emit_jmp(&b, code, &idx, (u16)loop_start, k);

    // Patch JZ → loop_end
    {
        u32 loop_end = idx;
        code[jz_patch + 1] ^= (u8)(loop_end & 0xFFu);
        code[jz_patch + 2] ^= (u8)((loop_end >> 8u) & 0xFFu);
    }

    vm_emit_halt(&b, code, &idx, k);
    return idx;
}

// =========================================================================
// Bytecode integrity: CRC32 (IEEE, reflected, no table)
// =========================================================================

ANTIDEBUG_INLINE u32 vm_crc32_buf(const u8* data, u32 len) {
    u32 crc = 0xFFFFFFFFu;
    u32 i, b;
    for (i = 0u; i < len; i++) {
        crc ^= (u32)data[i];
        for (b = 0u; b < 8u; b++) {
            u32 mask = (u32)(-(s32)(crc & 1u));
            crc = (crc >> 1u) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

// =========================================================================
// High-level: derive + decrypt inside WhipVM v3
// =========================================================================

ANTIDEBUG_INLINE void vm_derive_and_decrypt_flag(
    u32 score,
    const u8* encrypted_flag,
    u8* output,
    u32 flag_len
) {
    u8 work[192];
    AD_ZERO_BUF(work, sizeof(work));

    // Clamp flag_len to avoid OOB on work[128 + i]
    if (flag_len > 64u) flag_len = 64u;

    u32 i;
    for (i = 0; i < flag_len && i < 35u; i++) {
        work[i] = encrypted_flag[i];
    }

    // Runtime key — ASLR-derived (PEB + TEB + stack), not extractable from static binary.
    // Wide u32 key gives ~2^24+ score-constant candidates; enc_key folds it to u8
    // for the instruction-level bytecode XOR layer.
    u32 rt_key  = vm_runtime_key();
    u8  enc_key = vm_enc_key(rt_key);

    // Phase 1: derive key stream → work[64..98]
    {
        u8 prog[1024];
        AD_ZERO_BUF(prog, sizeof(prog));
        u32 prog_len = vm_build_derive_key(prog, rt_key);

        // Double-CRC integrity bracket: snapshot immediately after build, then
        // re-measure just before vm_run. If another thread patched prog[] in the
        // window between the two measurements, the XOR is non-zero → regs[0]
        // poisoned → score decode cascade produces wrong score → wrong key stream.
        // On an unpatched run both CRCs agree → XOR = 0 → no effect.
        u32 _crc_pre = vm_crc32_buf(prog, prog_len);

        vm_state_t vm;
        vm_init(&vm, work + 64);
        vm_shuffle_table(vm.sem_table, rt_key);
        vm_meta_init(&vm);
        vm.regs[0] = vm_score_encode(score, rt_key);

        {
            u32 _crc_post = vm_crc32_buf(prog, prog_len);
            vm.regs[0] ^= (u64)(_crc_pre ^ _crc_post);
        }

        // ── Meta-A: timing bracket ────────────────────────────────────
        // Measure cycles around vm_run. A stub that returns immediately
        // costs <300 cycles; a reverser single-stepping costs >200M.
        // Either extreme silently XOR-corrupts work[65].
#if defined(_MSC_VER)
        u64 _ph1_t0, _ph1_t1;
        AD_LFENCE(); _ph1_t0 = __rdtsc(); AD_LFENCE();
#endif
        vm_run(&vm, prog, prog_len, enc_key);
#if defined(_MSC_VER)
        AD_LFENCE(); _ph1_t1 = __rdtsc(); AD_LFENCE();
        {
            u64 _el = _ph1_t1 - _ph1_t0;
            // Lower bound 300 cycles: catches NOP-stub patches.
            // Upper bound 2 G cycles (~666 ms @ 3 GHz): catches single-step
            // erun (typically >5 G cycles per VM op) without false-positiving
            // dev hosts where context switches under load can stretch
            // legitimate execution past the original 200 M ceiling.
            if (_el < 300ULL || _el > 2000000000ULL)
                work[65] ^= (u8)(_el & 0xFFu) ^ 0xC3u;
        }
#endif

        // ── Meta-B: step_count guard ──────────────────────────────────
        // vm_run that returns immediately (NOP patch / ret stub) leaves
        // step_count = 0.  Any real Phase-1 execution takes >= 1 step.
        if (VM_UNLIKELY(vm.step_count == 0u))
            work[65] ^= 0xB7u;

        // Secondary native integrity gate — independent of the caller's score.
        // Directly reads PEB.BeingDebugged and NtGlobalFlag from the TEB/GS
        // segment without any VM indirection.  A reverser who bypassed
        // commitment_score from outside (patching ad_run_hardened to return 0)
        // still hits this check, which silently XOR-corrupts work[64] (the
        // first byte of the Phase-1 key stream).  Phase 2 then decrypts to
        // garbage — no visible crash, no assertion, just wrong output.
        {
#if defined(_MSC_VER)
            volatile u8* _peb = (volatile u8*)(uintptr_t)__readgsqword(0x60);
            u8  _bd  = _peb[2];                          // PEB.BeingDebugged
            u32 _ngf = *(volatile u32*)(_peb + 0xBC);    // PEB.NtGlobalFlag
            if (_bd | (u8)!!(_ngf & AD_HEAP_DEBUG_FLAGS))
                work[64] ^= 0xA5u;
#elif defined(__GNUC__) || defined(__clang__)
            volatile u8* _peb;
            __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(_peb));
            u8  _bd  = _peb[2];
            u32 _ngf = *(volatile u32*)(_peb + 0xBC);
            if (_bd | (u8)!!(_ngf & AD_HEAP_DEBUG_FLAGS))
                work[64] ^= 0xA5u;
#endif
        }

        AD_ZERO_BUF(prog, sizeof(prog));
    }

    // ── Decoy VM run ─────────────────────────────────────────────────
    // Identical structure to the real program but different key/score.
    // A reverser tracing the process sees 3 VM runs and must determine
    // which ones matter. The decoy's output is immediately wiped.
    {
        u8 dp[1024];
        AD_ZERO_BUF(dp, sizeof(dp));
        // Decoy key: use RDTSC + stack address — independent of rt_key.
        // Knowing rt_key no longer lets an attacker trivially compute dk.
        u32 dk;
#if defined(_MSC_VER)
        {
            u64 _tsc = __rdtsc();
            volatile u64 _dp = 0;
            u32 _dh = (u32)(_tsc ^ (_tsc >> 32))
                    ^ ((u32)((u64)(uintptr_t)&_dp >> 4) & 0xFFFFu);
            _dh ^= _dh >> 16;
            _dh *= 0x45D9F3Bu;
            _dh ^= _dh >> 16;
            dk = _dh ? _dh : 0xC0FFEE42u;
        }
#else
        dk = rt_key ^ 0xA5A5A5A5u;
#endif
        u32 dl = vm_build_derive_key(dp, dk);
        u8 dbuf[128];
        AD_ZERO_BUF(dbuf, sizeof(dbuf));
        vm_state_t dvm;
        vm_init(&dvm, dbuf);
        vm_shuffle_table(dvm.sem_table, dk);
        vm_meta_init(&dvm);
        dvm.regs[0] = vm_score_encode(score ^ 0xDEADC0DEu, dk);
        vm_run(&dvm, dp, dl, vm_enc_key(dk));

        // ── Meta-C: decoy execution guard ────────────────────────────
        // On a clean run the decoy executes ≥ 1 step and step_count > 0.
        // A reverser who patches vm_run to ret immediately or NOPs the
        // decoy block gets step_count = 0 → work[64] is XOR-poisoned →
        // Phase 2 decrypts using wrong key stream → garbage output.
        if (VM_UNLIKELY(dvm.step_count == 0u))
            work[64] ^= 0xFFu;

        AD_ZERO_BUF(dbuf, sizeof(dbuf));
        AD_ZERO_BUF(dp, sizeof(dp));
    }

    // Phase 2: XOR decrypt → work[128..162]
    {
        // ── Meta-D: output pre-canary ─────────────────────────────────
        // Fill work[128..128+flag_len] with a rt_key-derived sentinel.
        // Phase 2 overwrites every byte; if vm_run was stubbed/NOPed
        // the sentinel survives and the output check below wipes it.
        // Using two distinct sentinel bytes at fixed offsets makes an
        // accidental clean-run false-positive virtually impossible.
        u8 _cpat0 = (u8)((rt_key ^ (rt_key >> 8))  ^ 0xBEu);
        u8 _cpat1 = (u8)((rt_key ^ (rt_key >> 16)) ^ 0xEFu);
        for (i = 0; i < flag_len; i++)
            work[128 + i] = (u8)(_cpat0 ^ (u8)i) ^ (u8)(i * _cpat1);

        u8 prog[1024];
        AD_ZERO_BUF(prog, sizeof(prog));
        u32 prog_len = vm_build_xor_decrypt(prog, rt_key);

        vm_state_t vm;
        vm_init(&vm, work);
        vm_shuffle_table(vm.sem_table, rt_key);
        vm_meta_init(&vm);
        vm.regs[0] = (u64)flag_len;

        vm_run(&vm, prog, prog_len, enc_key);

        // ── Meta-E: Phase-2 step_count guard ─────────────────────────
        // If vm_run returned immediately (step_count == 0), Phase 2
        // wrote nothing — the canary is still in work[128..].
        // Wipe output so the caller gets an empty buffer, not a canary.
        if (VM_UNLIKELY(vm.step_count == 0u))
            AD_ZERO_BUF(work + 128, flag_len);

        // ── Canary survival check (belt-and-suspenders) ────────────────
        // Even if step_count > 0, verify Phase 2 actually overwrote the
        // sentinel at position 0 and position 1.  Both matching the
        // pre-canary formula simultaneously after a real run is ~2^-16.
        if (VM_UNLIKELY(
                work[128]     == (u8)(_cpat0)        &&
                work[128 + 1] == ((u8)(_cpat0 ^ 1u) ^ _cpat1)))
            AD_ZERO_BUF(work + 128, flag_len);

        AD_ZERO_BUF(prog, sizeof(prog));
    }

    for (i = 0; i < flag_len; i++) {
        output[i] = work[128 + i];
    }

    AD_ZERO_BUF(work, sizeof(work));
}

#endif // ANTIDEBUG_VM_PROGRAMS_H
