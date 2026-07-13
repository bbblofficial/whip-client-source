// ===== file: antidebug/vm/vm_cpp.hpp =====
//
// C++ wrapper for WhipVM — pre-compiled programs ready to use, plus a
// generic CompiledProgram for custom bytecode.
//
// Header-only. Pulls in the C VM headers under extern "C".
//
//     // Ready-to-use 4-stage cascade:
//     ad::vm::ScoreCascade cascade(KEY_A, KEY_B, KEY_C, KEY_D);
//     std::uint64_t enc = cascade.encode(my_score);
//     std::uint8_t  dec = cascade.run(my_score);  // round-trip via VM
//
//     // Custom bytecode you built via vm_dsl.h:
//     ad::vm::CompiledProgram prog(my_program_code, my_program_len);
//     std::uint8_t out = prog.run(input);
//
#ifndef ANTIDEBUG_VM_CPP_HPP
#define ANTIDEBUG_VM_CPP_HPP

#ifndef __cplusplus
#  error "vm_cpp.hpp requires C++"
#endif

#include <array>
#include <cstdint>
#include <span>

extern "C" {
#include "vm_interp.h"
#include "vm_programs.h"
#include "vm_dsl.h"
}

namespace ad::vm {

// ---------------------------------------------------------------------------
// CompiledProgram — owns a bytecode blob, caches the runtime key.
//
// The bytecode is built once (via vm_dsl.h or vm_programs.h builder) and
// re-run as many times as needed without rebuilding.
// ---------------------------------------------------------------------------
class CompiledProgram {
    const std::uint8_t* code_;
    std::uint32_t       code_len_;
    std::uint32_t       rt_key_;
public:
    CompiledProgram(const std::uint8_t* code, std::uint32_t len,
                    std::uint32_t rt_key = vm_runtime_key_stable())
        : code_(code), code_len_(len), rt_key_(rt_key) {}

    [[nodiscard]] std::uint8_t run(std::uint64_t input) const {
        return vm_dsl_run(code_, code_len_, rt_key_, input);
    }

    [[nodiscard]] std::uint32_t runtime_key() const noexcept { return rt_key_; }
    [[nodiscard]] std::uint32_t length()      const noexcept { return code_len_; }
};

// ---------------------------------------------------------------------------
// ScoreCascade — 4-stage cascade ((x ^ A) + B) * C ^ D, computed by the host
// for `encode()` and replayed by the VM for `run()`. The two paths must
// agree on a clean machine and diverge whenever the VM is tampered with.
//
// For most callers `encode()` is enough — it returns the host-side encoded
// value and matches what `vm_score_encode` produces in the C API.
// ---------------------------------------------------------------------------
class ScoreCascade {
    std::uint64_t a_, b_, c_, d_;
public:
    ScoreCascade(std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t d)
        : a_(a), b_(b), c_(c | 1ULL), d_(d) {}

    // Build from a runtime key using the canonical VM_KEY_A/B/C/D formulas.
    static ScoreCascade from_key(std::uint32_t rt_key) {
        return ScoreCascade(VM_KEY_A(rt_key), VM_KEY_B(rt_key),
                            VM_KEY_C(rt_key), VM_KEY_D(rt_key));
    }

    [[nodiscard]] std::uint64_t encode(std::uint32_t score) const {
        std::uint64_t v = score;
        v ^= a_; v += b_; v *= c_; v ^= d_;
        return v;
    }

    [[nodiscard]] std::uint32_t decode(std::uint64_t v) const {
        v ^= d_;
        v *= vm_mod_inverse(c_);
        v -= b_;
        v ^= a_;
        return static_cast<std::uint32_t>(v);
    }
};

// ---------------------------------------------------------------------------
// build_cascade_4 — emit a 4-stage cascade program into out_code via the
// raw builder. Returns the bytecode length.
//
// Equivalent to writing the body manually with vm_dsl.h:
//
//     VM_INPUT(r0)
//     VM_XOR_IMM(r0, ka)
//     VM_ADD_IMM(r0, kb)
//     VM_MUL_IMM(r0, kc)
//     VM_XOR_IMM(r0, kd)
//     VM_OUTPUT(r0)
//
// Output is the low byte of the final r0.
// ---------------------------------------------------------------------------
inline std::uint32_t build_cascade_4(std::uint8_t* out_code,
                                     std::uint32_t out_size,
                                     std::uint64_t ka, std::uint64_t kb,
                                     std::uint64_t kc, std::uint64_t kd,
                                     std::uint8_t base_key = VM_KEY_DEFAULT) {
    if (out_size < 96u) return 0u;  // worst-case ≈ 80 bytes; pad
    vm_builder_t b{};
    vm_builder_init(&b);
    std::uint32_t idx = 0u;
    const std::uint8_t k = base_key;

    // r0 ← input low byte
    vm_emit_load8(&b, out_code, &idx, 0u, k);

    // r0 ^= ka
    vm_emit_mov_ri(&b, out_code, &idx, 7u, ka, k);
    vm_emit_rr    (&b, out_code, &idx, SEM_XOR, 0u, 7u, k);

    // r0 += kb
    vm_emit_mov_ri(&b, out_code, &idx, 7u, kb, k);
    vm_emit_rr    (&b, out_code, &idx, SEM_ADD, 0u, 7u, k);

    // r0 *= (kc | 1)
    vm_emit_mov_ri(&b, out_code, &idx, 7u, kc | 1ULL, k);
    vm_emit_rr    (&b, out_code, &idx, SEM_MUL, 0u, 7u, k);

    // r0 ^= kd
    vm_emit_mov_ri(&b, out_code, &idx, 7u, kd, k);
    vm_emit_rr    (&b, out_code, &idx, SEM_XOR, 0u, 7u, k);

    // store to data[1]
    vm_emit_mov_ri(&b, out_code, &idx, 6u, 1ULL, k);
    vm_emit_store8(&b, out_code, &idx, 6u, 0u, k);

    vm_emit_halt(&b, out_code, &idx, k);
    return idx;
}

} // namespace ad::vm

#endif // ANTIDEBUG_VM_CPP_HPP
