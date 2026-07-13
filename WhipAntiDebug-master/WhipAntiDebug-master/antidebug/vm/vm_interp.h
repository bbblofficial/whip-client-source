// ===== file: antidebug/vm/vm_interp.h =====
//
// WhipVM v3.1 — chaotic deterministic VM with riscvm hardening layer
//
// Borrowed from riscy-business (riscvm):
//   - tetra_twist hash  (strong avalanche, replaces murmur in key derivation)
//   - vm_fetch()        (clean opcode-fetch pattern)
//   - Handler table     (indirect dispatch via g_vm_handlers[], no switch)
//   - Threaded dispatch (musttail on Clang — each handler tail-calls the next)
//   - VM_LIKELY/VM_UNLIKELY branch hints
//   - NOINLINE on vm_run (eliminates visible dispatch loop in disasm)
//
// WhipVM-native features retained:
//   Semantic drift, observer effect, history-chain keys, entangled registers,
//   ghost banks, memory aliasing, ASLR table shuffle, SEM_SYSCALL/TRAP/FUSE
//
#ifndef ANTIDEBUG_VM_INTERP_H
#define ANTIDEBUG_VM_INTERP_H

#include "../core/types.h"
#include "../core/macros.h"

// =========================================================================
// Branch-prediction hints (riscvm)
// =========================================================================
#if defined(__GNUC__) || defined(__clang__)
#  define VM_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define VM_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#  define VM_LIKELY(x)   (x)
#  define VM_UNLIKELY(x) (x)
#endif

// =========================================================================
// Musttail — true threaded dispatch on Clang, graceful fallback elsewhere
// =========================================================================
#if defined(__clang__)
#  if __has_attribute(musttail)
#    define VM_HAS_MUSTTAIL 1
#    define VM_MUSTTAIL     __attribute__((musttail))
#  else
#    define VM_HAS_MUSTTAIL 0
#    define VM_MUSTTAIL
#  endif
#else
#  define VM_HAS_MUSTTAIL 0
#  define VM_MUSTTAIL
#endif

// =========================================================================
// Raw opcode bytes — meaning resolved at runtime via semantic table
// =========================================================================
#define VM_OP_00  0x00
#define VM_OP_01  0x01
#define VM_OP_02  0x02
#define VM_OP_03  0x03
#define VM_OP_04  0x04
#define VM_OP_05  0x05
#define VM_OP_06  0x06
#define VM_OP_07  0x07
#define VM_OP_08  0x08
#define VM_OP_09  0x09
#define VM_OP_0A  0x0A
#define VM_OP_0B  0x0B
#define VM_OP_0C  0x0C
#define VM_OP_0D  0x0D
#define VM_OP_0E  0x0E
#define VM_OP_0F  0x0F

// =========================================================================
// Semantic actions
// =========================================================================
typedef enum {
    SEM_NOP       = 0,
    SEM_HALT      = 1,
    SEM_MOV_RI    = 2,
    SEM_MOV_RR    = 3,
    SEM_MOV_RA    = 4,
    SEM_MOV_AR    = 5,
    SEM_ADD       = 6,
    SEM_XOR       = 7,
    SEM_MUL       = 8,
    SEM_AND       = 9,
    SEM_SHR       = 10,
    SEM_CMP       = 11,
    SEM_JMP       = 12,
    SEM_JZ        = 13,
    SEM_JNZ       = 14,
    SEM_LOAD8     = 15,
    SEM_STORE8    = 16,
    SEM_GHOST     = 17,
    SEM_MERGE     = 18,
    SEM_ENTANGLE  = 19,
    SEM_DRIFT     = 20,
    SEM_OBSERVE   = 21,
    SEM_QUANTUM   = 22,
    SEM_ALIAS     = 23,
    SEM_INTEGRITY = 24,
    SEM_SYSCALL   = 25,
    SEM_TRAP      = 26,
    SEM_FUSE      = 27,
    SEM_COUNT     = 28
} vm_semantic_t;

// =========================================================================
// VM state
// =========================================================================
#define VM_NUM_REGS    8u
#define VM_STACK_SZ    16u
#define VM_HIST_SZ     4u
#define VM_ALIAS_SLOTS 4u

typedef struct {
    u64 regs[VM_NUM_REGS];
    u64 shadow[VM_NUM_REGS];
    u64 acc;
    u64 xacc;
    u64 stack[VM_STACK_SZ];
    u32 sp;
    u32 pc;
    b32 zf;
    b32 cf;
    b32 halted;
    u32 step_count;

    u8  sem_table[16];
    u64 drift_state;
    u32 drift_rotation_count;

    u8  history[VM_HIST_SZ];
    u32 hist_idx;

    u8  entangle_pairs[VM_NUM_REGS];

    u64 last_tsc;
    u32 observer_shift;

    u32 alias_counter[VM_ALIAS_SLOTS];
    u64 alias_base[VM_ALIAS_SLOTS];

    u64 chaos;
    u8* data_base;

    u8  cur_key;    // per-instruction operand key, set by dispatch before handler entry

    // ── Meta-protection fields ───────────────────────────────────────
    u64 state_canary;   // struct tamper sentinel (data_base-derived)
    u32 sem_hash;       // FNV-32 of sem_table after init — detects table patching
    u32 handler_stamp;  // tetra_twist rolling hash of handler entry bytes
} vm_state_t;

// =========================================================================
// tetra_twist — from riscvm (strong avalanche, replaces previous murmur hash)
// Same prime, same mix rounds, same avalanche guarantee.
// =========================================================================
ANTIDEBUG_INLINE u32 vm_tetra_twist(u32 input) {
    static const u32 prime1 = 0x9E3779B1u;
    input ^= input >> 15;
    input *= prime1;
    input ^= input >> 12;
    input *= prime1;
    input ^= input >> 4;
    input *= prime1;
    input ^= input >> 16;
    return input;
}

// =========================================================================
// History-chain key — PC-mixed, tetra_twist avalanche (was plain murmur)
// =========================================================================
ANTIDEBUG_INLINE u8 vm_history_key(const vm_state_t* vm, u8 base_key) {
    u32 h = (u32)base_key ^ (vm->pc * 0x9E3779B9u);
    return (u8)(vm_tetra_twist(h) & 0xFFu);
}

// =========================================================================
// vm_fetch — clean one-byte fetch + XOR decrypt (riscvm pattern)
// =========================================================================
ANTIDEBUG_INLINE u8 vm_fetch(vm_state_t* vm, const u8* code, u8 key) {
    u8 val = code[vm->pc] ^ key;
    vm->pc++;
    return val;
}

// =========================================================================
// Chaos PRNG
// =========================================================================
ANTIDEBUG_INLINE u64 vm_chaos_next(vm_state_t* vm) {
    u64 x = vm->chaos;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    vm->chaos = x;
    return x;
}

// =========================================================================
// Initialisation
// =========================================================================
ANTIDEBUG_INLINE void vm_init(vm_state_t* vm, u8* data_base) {
    AD_ZERO_BUF(vm, sizeof(*vm));
    vm->data_base = data_base;
    vm->chaos     = 0xDEADC0DE42424242ULL;

    vm->sem_table[0x00] = SEM_MOV_RI;
    vm->sem_table[0x01] = SEM_SYSCALL;
    vm->sem_table[0x02] = SEM_MOV_RA;
    vm->sem_table[0x03] = SEM_TRAP;
    vm->sem_table[0x04] = SEM_ADD;
    vm->sem_table[0x05] = SEM_XOR;
    vm->sem_table[0x06] = SEM_MUL;
    vm->sem_table[0x07] = SEM_AND;
    vm->sem_table[0x08] = SEM_CMP;
    vm->sem_table[0x09] = SEM_JMP;
    vm->sem_table[0x0A] = SEM_JZ;
    vm->sem_table[0x0B] = SEM_LOAD8;
    vm->sem_table[0x0C] = SEM_STORE8;
    vm->sem_table[0x0D] = SEM_HALT;
    vm->sem_table[0x0E] = SEM_GHOST;
    vm->sem_table[0x0F] = SEM_NOP;

    u32 i;
    for (i = 0; i < VM_NUM_REGS; i++)
        vm->entangle_pairs[i] = (u8)i;

#if defined(_MSC_VER)
    vm->last_tsc = __rdtsc();
#endif
}

// =========================================================================
// Semantic drift — evolves hidden state each step
// =========================================================================
ANTIDEBUG_INLINE void vm_drift_semantics(vm_state_t* vm) {
    vm->drift_state ^= vm_chaos_next(vm);
    vm->drift_state ^= (u64)vm->step_count * 0x9E3779B97F4A7C15ULL;
    vm->drift_rotation_count++;
}

// =========================================================================
// PC-based semantic rotation
// =========================================================================
#define VM_DRIFT_PC_ROT(pc) (((pc) * 7u) & 0x0Fu)

ANTIDEBUG_INLINE vm_semantic_t vm_resolve_action(const u8* sem_table, u8 raw_op, u32 pc) {
    u32 vrot = VM_DRIFT_PC_ROT(pc);
    u8  idx  = (u8)(((raw_op & 0x0Fu) + vrot) & 0x0Fu);
    return (vm_semantic_t)sem_table[idx];
}

// =========================================================================
// History chain
// =========================================================================
ANTIDEBUG_INLINE void vm_history_push(vm_state_t* vm, u8 opcode) {
    vm->history[vm->hist_idx & (VM_HIST_SZ - 1u)] = opcode;
    vm->hist_idx++;
}

// =========================================================================
// Observer effect — debugger single-step produces timing anomaly
// =========================================================================
ANTIDEBUG_INLINE void vm_observer_check(vm_state_t* vm) {
#if defined(_MSC_VER)
    u64 now   = __rdtsc();
    u64 delta = now - vm->last_tsc;
    vm->last_tsc = now;
    if (VM_UNLIKELY(delta > 50000ULL && vm->step_count > 100u))
        vm->observer_shift++;
#endif
}

// =========================================================================
// Entanglement write
// =========================================================================
ANTIDEBUG_INLINE void vm_entangle_write(vm_state_t* vm, u32 reg_idx, u64 value) {
    vm->regs[reg_idx] = value;
    u32 partner = (u32)vm->entangle_pairs[reg_idx];
    if (VM_LIKELY(partner == reg_idx)) return;
    u32 rot     = (partner * 7u) & 63u;
    u64 rotated = rot ? ((value << rot) | (value >> (64u - rot))) : value;
    vm->regs[partner] ^= rotated;
}

// =========================================================================
// Memory aliasing read
// =========================================================================
ANTIDEBUG_INLINE u8 vm_alias_read(vm_state_t* vm, u32 addr) {
    if (!vm->data_base) return 0;
    u8  raw        = vm->data_base[addr];
    u32 alias_slot = (addr >> 6) & (VM_ALIAS_SLOTS - 1u);
    u32 counter    = vm->alias_counter[alias_slot];
    vm->alias_counter[alias_slot]++;
    if (counter == 0u) {
        vm->alias_base[alias_slot] = (u64)raw;
        return raw;
    }
    u8 scramble = (u8)((counter * 0x6Bu) ^ (alias_slot * 0x37u)
                      ^ (u8)(vm->alias_base[alias_slot] >> 3));
    return (u8)(raw ^ scramble);
}

// =========================================================================
// Multi-byte operand readers (used by handlers)
// =========================================================================
ANTIDEBUG_INLINE u16 vm_read_u16(vm_state_t* vm, const u8* code, u8 key) {
    u8 lo = vm_fetch(vm, code, key);
    u8 hi = vm_fetch(vm, code, key);
    return (u16)lo | ((u16)hi << 8);
}

ANTIDEBUG_INLINE u64 vm_read_u64(vm_state_t* vm, const u8* code, u8 key) {
    u64 val = 0; u32 i;
    for (i = 0; i < 8u; i++)
        val |= (u64)vm_fetch(vm, code, key) << (i * 8u);
    return val;
}

// =========================================================================
// ASLR-seeded Fisher-Yates table shuffle
// =========================================================================
ANTIDEBUG_INLINE void vm_shuffle_table(u8* sem_table, u32 rt_key) {
    u64 s = 0xDEADC0DE42424242ULL ^ ((u64)rt_key * 0x9E3779B97F4A7C15ULL);
    u32 i;
    for (i = 15; i > 0; i--) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        u32 j   = (u32)(s % (i + 1u));
        u8  tmp = sem_table[i];
        sem_table[i] = sem_table[j];
        sem_table[j] = tmp;
    }
}

// =========================================================================
// Handler type and forward declarations
// All handlers share the same signature so musttail tail-calls are valid.
// =========================================================================
typedef void (*vm_handler_t)(vm_state_t* vm, u8* code, u8 base_key);

static void vh_nop      (vm_state_t*, u8*, u8);
static void vh_halt     (vm_state_t*, u8*, u8);
static void vh_mov_ri   (vm_state_t*, u8*, u8);
static void vh_mov_rr   (vm_state_t*, u8*, u8);
static void vh_mov_ra   (vm_state_t*, u8*, u8);
static void vh_mov_ar   (vm_state_t*, u8*, u8);
static void vh_add      (vm_state_t*, u8*, u8);
static void vh_xor      (vm_state_t*, u8*, u8);
static void vh_mul      (vm_state_t*, u8*, u8);
static void vh_and      (vm_state_t*, u8*, u8);
static void vh_shr      (vm_state_t*, u8*, u8);
static void vh_cmp      (vm_state_t*, u8*, u8);
static void vh_jmp      (vm_state_t*, u8*, u8);
static void vh_jz       (vm_state_t*, u8*, u8);
static void vh_jnz      (vm_state_t*, u8*, u8);
static void vh_load8    (vm_state_t*, u8*, u8);
static void vh_store8   (vm_state_t*, u8*, u8);
static void vh_ghost    (vm_state_t*, u8*, u8);
static void vh_merge    (vm_state_t*, u8*, u8);
static void vh_entangle (vm_state_t*, u8*, u8);
static void vh_drift    (vm_state_t*, u8*, u8);
static void vh_observe  (vm_state_t*, u8*, u8);
static void vh_quantum  (vm_state_t*, u8*, u8);
static void vh_alias    (vm_state_t*, u8*, u8);
static void vh_integrity(vm_state_t*, u8*, u8);
static void vh_syscall  (vm_state_t*, u8*, u8);
static void vh_trap     (vm_state_t*, u8*, u8);
static void vh_fuse     (vm_state_t*, u8*, u8);

// =========================================================================
// Handler dispatch table — indexed by vm_semantic_t value.
// Indirect branch via function pointer: no switch, no visible opcode map.
// A static analyser sees only an array of code pointers; the opcode→index
// mapping is hidden behind the runtime semantic table and PC-rotation.
// =========================================================================
static const vm_handler_t g_vm_handlers[SEM_COUNT] = {
    vh_nop,       /* SEM_NOP       = 0  */
    vh_halt,      /* SEM_HALT      = 1  */
    vh_mov_ri,    /* SEM_MOV_RI    = 2  */
    vh_mov_rr,    /* SEM_MOV_RR    = 3  */
    vh_mov_ra,    /* SEM_MOV_RA    = 4  */
    vh_mov_ar,    /* SEM_MOV_AR    = 5  */
    vh_add,       /* SEM_ADD       = 6  */
    vh_xor,       /* SEM_XOR       = 7  */
    vh_mul,       /* SEM_MUL       = 8  */
    vh_and,       /* SEM_AND       = 9  */
    vh_shr,       /* SEM_SHR       = 10 */
    vh_cmp,       /* SEM_CMP       = 11 */
    vh_jmp,       /* SEM_JMP       = 12 */
    vh_jz,        /* SEM_JZ        = 13 */
    vh_jnz,       /* SEM_JNZ       = 14 */
    vh_load8,     /* SEM_LOAD8     = 15 */
    vh_store8,    /* SEM_STORE8    = 16 */
    vh_ghost,     /* SEM_GHOST     = 17 */
    vh_merge,     /* SEM_MERGE     = 18 */
    vh_entangle,  /* SEM_ENTANGLE  = 19 */
    vh_drift,     /* SEM_DRIFT     = 20 */
    vh_observe,   /* SEM_OBSERVE   = 21 */
    vh_quantum,   /* SEM_QUANTUM   = 22 */
    vh_alias,     /* SEM_ALIAS     = 23 */
    vh_integrity, /* SEM_INTEGRITY = 24 */
    vh_syscall,   /* SEM_SYSCALL   = 25 */
    vh_trap,      /* SEM_TRAP      = 26 */
    vh_fuse,      /* SEM_FUSE      = 27 */
};

// =========================================================================
// VM_DISPATCH — the core threading macro (riscvm threaded-code pattern).
//
// Clang + musttail:
//   Each handler ends with VM_DISPATCH → tail-call to next handler.
//   The entire VM execution is a chain of tail-calls — no visible loop.
//   Disassembly shows a web of indirect JMPs, never a single dispatch loop.
//
// MSVC / other compilers:
//   VM_DISPATCH is not used inside handlers. Instead vm_run contains the
//   while loop and calls handlers via g_vm_handlers[] (indirect branch).
//   Still significantly harder to analyse than a switch statement.
// =========================================================================
// =========================================================================
// vm_guard_check — instruction guard bits (riscvm compressed_flags pattern).
//
// All valid WhipVM opcodes use only the lower 4 bits (0x00-0x0F).
// After XOR-decryption the upper 4 bits of a valid byte must be zero.
// If not: the key diverged (e.g. bytecode was patched, or single-step
// desynchronised a history-based derivative) — silently increment
// observer_shift so the semantic table drifts to wrong values without
// crashing or producing any visible error.  A reverser sees "ran to
// completion, output is garbage" with no obvious cause.
// =========================================================================
ANTIDEBUG_INLINE void vm_guard_check(vm_state_t* vm, u8 raw) {
    if (VM_UNLIKELY((raw & 0xF0u) != 0u))
        vm->observer_shift++;
}

// =========================================================================
// Meta-protection helpers
// =========================================================================

// Derive the expected state canary from the (stable) data_base pointer.
// The formula folds the pointer through two independent tetra_twist calls
// so upper and lower 32 bits of the address both contribute.
ANTIDEBUG_INLINE u64 vm_canary_from_ptr(const u8* data_base) {
    u64 lo = (u64)vm_tetra_twist((u32)(uintptr_t)data_base);
    u64 hi = (u64)vm_tetra_twist((u32)((uintptr_t)data_base >> 16));
    return (lo ^ (hi << 32)) ^ 0xDEADC0DECAFE1337ULL;
}

// vm_meta_init — call once after vm_init + vm_shuffle_table, before vm_run.
// Snapshots the three meta-protection values into vm_state_t.
ANTIDEBUG_INLINE void vm_meta_init(vm_state_t* vm) {
    // 1. State canary
    vm->state_canary = vm_canary_from_ptr(vm->data_base);

    // 2. sem_table FNV-32 (16 bytes)
    u32 fh = 0x811C9DC5u;
    u32 i;
    for (i = 0u; i < 16u; i++) {
        fh ^= (u32)vm->sem_table[i];
        fh *= 0x01000193u;
    }
    vm->sem_hash = fh;

    // 3. Handler prologue stamp — tetra_twist rolling hash of the first 16
    //    bytes of every handler function.  Covers both entry-byte hooks (INT3,
    //    JMP) and mid-prologue patches that skip the first byte.
    u32 hp = 0x5EED1234u;
    u32 j;
    for (i = 0u; i < SEM_COUNT; i++) {
        volatile const u8* p = (volatile const u8*)(uintptr_t)g_vm_handlers[i];
        for (j = 0u; j < 16u; j++)
            hp = vm_tetra_twist(hp ^ (u32)p[j] ^ (u32)(i * 0x13u + j * 0x07u));
    }
    vm->handler_stamp = hp;
}

// vm_meta_check — called from the vm_run loop.
// Any mismatch silently increments observer_shift, poisoning the semantic
// table just like physical timing anomalies.  A reverser who patches one
// field must also find and neutralise this check to avoid corrupted output.
ANTIDEBUG_INLINE void vm_meta_check(vm_state_t* vm) {
    u32 i;

    // 1. Canary
    if (VM_UNLIKELY(vm->state_canary != vm_canary_from_ptr(vm->data_base)))
        vm->observer_shift++;

    // 2. sem_table hash
    u32 fh = 0x811C9DC5u;
    for (i = 0u; i < 16u; i++) {
        fh ^= (u32)vm->sem_table[i];
        fh *= 0x01000193u;
    }
    if (VM_UNLIKELY(fh != vm->sem_hash))
        vm->observer_shift++;

    // 3. Handler prologue scan + stamp re-verify (16 bytes per handler)
    u32 hp = 0x5EED1234u;
    u32 j;
    for (i = 0u; i < SEM_COUNT; i++) {
        volatile const u8* p = (volatile const u8*)(uintptr_t)g_vm_handlers[i];
        u8 b0 = *p;
        // INT3 (0xCC) or unconditional JMP (0xE9) at entry = code has been hooked
        if (VM_UNLIKELY(b0 == 0xCCu || b0 == 0xE9u))
            vm->observer_shift++;
        for (j = 0u; j < 16u; j++)
            hp = vm_tetra_twist(hp ^ (u32)p[j] ^ (u32)(i * 0x13u + j * 0x07u));
    }
    if (VM_UNLIKELY(hp != vm->handler_stamp))
        vm->observer_shift++;
}

#if VM_HAS_MUSTTAIL
#define VM_DISPATCH(vm, code, base_key)                                        \
    do {                                                                       \
        if (VM_UNLIKELY((vm)->halted ||                                        \
                        (vm)->step_count >= VM_MAX_STEPS)) return;             \
        vm_observer_check(vm);                                                 \
        if (VM_UNLIKELY(((vm)->step_count & 63u) == 0u))                       \
            vm_meta_check(vm);                                                 \
        {   u8 _k = vm_history_key(vm, base_key);                             \
            (vm)->cur_key = _k;                                                \
            u8 _r = vm_fetch(vm, code, _k);                                   \
            vm_guard_check(vm, _r);                                            \
            vm_history_push(vm, _r);                                           \
            vm_semantic_t _a = vm_resolve_action((vm)->sem_table, _r,         \
                                                  (vm)->pc - 1u);             \
            if (VM_UNLIKELY((vm)->observer_shift > 0u))                        \
                _a = (vm_semantic_t)((_a + (vm)->observer_shift) % SEM_COUNT); \
            VM_MUSTTAIL return g_vm_handlers[_a](vm, code, base_key);         \
        }                                                                      \
    } while(0)
#endif

// VM_STEP_END — post-step boilerplate placed at the end of every handler.
// Clang: advance drift, bump counter, tail-call next handler (threading).
// MSVC:  nothing — vm_run loop handles drift and counter externally.
#if VM_HAS_MUSTTAIL
#  define VM_STEP_END(vm, code, key)   \
     do {                             \
         vm_drift_semantics(vm);      \
         (vm)->step_count++;          \
         VM_DISPATCH(vm, code, key);  \
     } while(0)
#else
#  define VM_STEP_END(vm, code, key)   \
     do { AD_UNUSED(code); AD_UNUSED(key); } while(0)
#endif

// =========================================================================
// Handler implementations
// NOINLINE: keeps each handler as a distinct function — on Clang this gives
// the chain of indirect JMPs; on MSVC it keeps the call sites small.
// =========================================================================

static NOINLINE void vh_nop(vm_state_t* vm, u8* code, u8 base_key) {
    vm_chaos_next(vm);
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_halt(vm_state_t* vm, u8* code, u8 base_key) {
    vm->halted = 1;
    AD_UNUSED(code); AD_UNUSED(base_key);
}

static NOINLINE void vh_mov_ri(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rn  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    u64 imm = vm_read_u64(vm, code, key);
    vm_entangle_write(vm, rn, imm);
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_mov_rr(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rd  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    u32 rs  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    vm_entangle_write(vm, rd, vm->regs[rs]);
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_mov_ra(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rn  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    vm_entangle_write(vm, rn, vm->acc);
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_mov_ar(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rn  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    vm->acc = vm->regs[rn];
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_add(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rd  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    u32 rs  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    vm->acc  = vm->regs[rd] + vm->regs[rs];
    vm->xacc = vm->regs[rs] + vm->regs[rd];
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_xor(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rd  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    u32 rs  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    vm->acc = vm->regs[rd] ^ vm->regs[rs];
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_mul(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rd  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    u32 rs  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    vm->acc = vm->regs[rd] * vm->regs[rs];
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_and(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rd  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    u32 rs  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    vm->acc = vm->regs[rd] & vm->regs[rs];
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_shr(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rd  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    u32 rs  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    vm->acc = vm->regs[rd] >> (vm->regs[rs] & 63u);
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_cmp(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rd  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    u32 rs  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    vm->zf  = (b32)(vm->regs[rd] == vm->regs[rs]);
    vm->cf  = (b32)(vm->regs[rd] <  vm->regs[rs]);
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_jmp(vm_state_t* vm, u8* code, u8 base_key) {
    u16 target = vm_read_u16(vm, code, vm->cur_key);
    vm->pc = (u32)target;
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_jz(vm_state_t* vm, u8* code, u8 base_key) {
    u16 target = vm_read_u16(vm, code, vm->cur_key);
    if (vm->zf) vm->pc = (u32)target;
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_jnz(vm_state_t* vm, u8* code, u8 base_key) {
    u16 target = vm_read_u16(vm, code, vm->cur_key);
    if (!vm->zf) vm->pc = (u32)target;
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_load8(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rn  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    if (VM_LIKELY(vm->data_base != 0))
        vm->acc = (u64)vm->data_base[(u32)vm->regs[rn]];
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_store8(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rd  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    u32 rs  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    if (VM_LIKELY(vm->data_base != 0))
        vm->data_base[(u32)vm->regs[rd]] = (u8)(vm->regs[rs] & 0xFFu);
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_ghost(vm_state_t* vm, u8* code, u8 base_key) {
    u32 i;
    for (i = 0; i < VM_NUM_REGS; i++) {
        u64 tmp       = vm->regs[i];
        vm->regs[i]   = vm->shadow[i];
        vm->shadow[i] = tmp;
    }
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_merge(vm_state_t* vm, u8* code, u8 base_key) {
    vm->acc ^= vm->xacc;
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_entangle(vm_state_t* vm, u8* code, u8 base_key) {
    u64 c = vm_chaos_next(vm);
    u32 i;
    for (i = 0; i < VM_NUM_REGS; i++)
        vm->entangle_pairs[i] = (u8)((c >> (i * 3u)) & 7u);
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_drift(vm_state_t* vm, u8* code, u8 base_key) {
    u8  tmp = vm->sem_table[0];
    u32 i;
    for (i = 0; i < 15u; i++)
        vm->sem_table[i] = vm->sem_table[i + 1u];
    vm->sem_table[15] = tmp;
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_observe(vm_state_t* vm, u8* code, u8 base_key) {
#if defined(_MSC_VER)
    vm->acc = __rdtsc();
#else
    vm->acc = 0;
#endif
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_quantum(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key = vm->cur_key;
    u32 rd  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    u32 rs  = (u32)(vm_fetch(vm, code, key) & 0x07u);
    vm->acc  = vm->regs[rd] + vm->regs[rs];
    vm->xacc = vm->regs[rd] ^ vm->regs[rs];
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_alias(vm_state_t* vm, u8* code, u8 base_key) {
    u8 slot = vm_fetch(vm, code, vm->cur_key) & (VM_ALIAS_SLOTS - 1u);
    vm->alias_counter[slot]++;
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_integrity(vm_state_t* vm, u8* code, u8 base_key) {
    u8  len  = vm_fetch(vm, code, vm->cur_key);
    u64 hash = 0xCBF29CE484222325ULL;
    u32 ci;
    for (ci = 0; ci < (u32)len && ci < 64u; ci++) {
        hash ^= (u64)code[vm->pc + ci];
        hash *= 0x00000100000001B3ULL;
    }
    if (VM_UNLIKELY(hash != vm->acc)) {
        vm->acc  ^= hash;
        vm->xacc ^= 0xDEADDEADDEADDEADULL;
    }
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_syscall(vm_state_t* vm, u8* code, u8 base_key) {
    u8  check_id = vm_fetch(vm, code, vm->cur_key) & 0x07u;
    u64 result   = 0;
#if defined(_MSC_VER)
    switch (check_id) {
    case 0: {
        u8* peb = (u8*)__readgsqword(0x60);
        result = (u64)(peb ? peb[0x02] : 0);
        break;
    }
    case 1: {
        u8* peb = (u8*)__readgsqword(0x60);
        result = peb ? (u64)(*(u32*)(peb + 0xBC) & 0x70u) : 0;
        break;
    }
    case 2: {
        volatile u8* kusd = (volatile u8*)0x7FFE0000ULL;
        result = (u64)*(volatile u8*)(kusd + 0x02D4);
        break;
    }
    case 3: {
        u64 now   = __rdtsc();
        u64 delta = now - vm->last_tsc;
        result = (delta > 50000ULL) ? delta : 0ULL;
        break;
    }
    case 4: {
        u64 t1 = __rdtsc(), t2 = __rdtsc(), t3 = __rdtsc();
        u64 d1 = t2 - t1, d2 = t3 - t2;
        result = (d1 > 5000ULL || d2 > 5000ULL || d1 == 0ULL) ? (d1 + d2) : 0ULL;
        break;
    }
    case 5: {
        u8* peb = (u8*)__readgsqword(0x60);
        if (peb) {
            u8* heap = *(u8**)(peb + 0x30);
            if (heap) {
                u32 fflags = *(u32*)(heap + 0x74);
                result = (u64)(fflags & 0x6Du);
            }
        }
        break;
    }
    }
#else
    AD_UNUSED(check_id);
#endif
    vm->acc = result;
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_trap(vm_state_t* vm, u8* code, u8 base_key) {
#if defined(_MSC_VER)
    volatile b32 handler_fired = 0;
    __try    { __int2c(); }
    __except(1) { handler_fired = 1; }
    vm->acc = handler_fired ? 0ULL : 0xDEADULL;
#else
    vm->acc = 0;
#endif
    VM_STEP_END(vm, code, base_key);
}

static NOINLINE void vh_fuse(vm_state_t* vm, u8* code, u8 base_key) {
    u8  key      = vm->cur_key;
    u32 rd       = (u32)(vm_fetch(vm, code, key) & 0x07u);
    u32 rs       = (u32)(vm_fetch(vm, code, key) & 0x07u);
    u8  next_raw = code[vm->pc] ^ key;
    u8  next_sem = vm->sem_table[next_raw & 0x0Fu];
    u64 a = vm->regs[rd], b = vm->regs[rs], c = vm_chaos_next(vm);
    switch (next_sem & 3u) {
    case 0: vm->acc = (a + b) ^ c;          break;
    case 1: vm->acc = (a ^ b) + c;          break;
    case 2: vm->acc = (a * b) ^ (c >> 3);   break;
    case 3: vm->acc = (a & b) | (c & ~b);   break;
    }
    vm->pc++;   /* consume the fused opcode */
    VM_STEP_END(vm, code, base_key);
}

// =========================================================================
// VM_MAX_STEPS safety cap
// =========================================================================
#define VM_MAX_STEPS 8192u

// =========================================================================
// vm_run — NOINLINE so the disassembler sees a clean call boundary.
//
// Clang: bootstraps the threaded handler chain with one dispatch call.
//        Execution is a chain of tail-calls; no loop visible in the binary.
//
// MSVC:  while loop with g_vm_handlers[] indirect dispatch.
//        Still no switch statement — analyser sees call-through-table only.
// =========================================================================
static NOINLINE void vm_run(
    vm_state_t* vm,
    u8*         code,
    u32         bytecode_len,
    u8          base_key
) {
    AD_UNUSED(bytecode_len);

#if VM_HAS_MUSTTAIL
    // Clang path: one dispatch bootstraps the whole chain.
    VM_DISPATCH(vm, code, base_key);
#else
    // MSVC path: trampoline loop, indirect dispatch table, no switch.
    vm_meta_check(vm);   // meta-check before first instruction
    while (VM_LIKELY(!vm->halted) && VM_LIKELY(vm->step_count < VM_MAX_STEPS)) {
        vm_observer_check(vm);
        if (VM_UNLIKELY((vm->step_count & 63u) == 0u))
            vm_meta_check(vm);
        u8 key      = vm_history_key(vm, base_key);
        vm->cur_key = key;
        u8 raw      = vm_fetch(vm, code, key);
        vm_guard_check(vm, raw);
        vm_history_push(vm, raw);
        vm_semantic_t act = vm_resolve_action(vm->sem_table, raw, vm->pc - 1u);
        if (VM_UNLIKELY(vm->observer_shift > 0u))
            act = (vm_semantic_t)((act + vm->observer_shift) % SEM_COUNT);
        g_vm_handlers[act](vm, code, base_key);
        vm_drift_semantics(vm);
        vm->step_count++;
    }
#endif
}

// =========================================================================
// Builder infrastructure (unchanged — vm_programs.h depends on these)
// =========================================================================

ANTIDEBUG_INLINE u8 vm_build_key(u8 base_key, u32 pc, u64 drift_state) {
    AD_UNUSED(drift_state);
    u32 h = (u32)base_key ^ (pc * 0x9E3779B9u);
    return (u8)(vm_tetra_twist(h) & 0xFFu);
}

ANTIDEBUG_INLINE u8 vm_resolve_opcode(const u8* sem_table, vm_semantic_t action, u32 pc) {
    u32 vrot = VM_DRIFT_PC_ROT(pc);
    u32 i;
    for (i = 0; i < 16u; i++) {
        if (sem_table[((i + vrot) & 0x0Fu)] == (u8)action) return (u8)i;
    }
    return 0x0Fu;
}

ANTIDEBUG_INLINE void vm_build_drift(u8* sem_table, u64* drift_state, u64* chaos,
                                      u32 step, u32* drift_rotation_count) {
    u64 x = *chaos;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *chaos = x;
    *drift_state ^= x;
    *drift_state ^= (u64)step * 0x9E3779B97F4A7C15ULL;
    (*drift_rotation_count)++;
    AD_UNUSED(sem_table);
}

#define VM_ENC(byte, key) ((u8)((byte) ^ (key)))

#endif // ANTIDEBUG_VM_INTERP_H
