// ===== file: antidebug/core/flag_honeypot.h =====
//
// Honeypot flag strings — traps for automated solvers and string-based
// reversers.
//
// The real flag is built on the stack from encrypted runtime state. A
// reverser who runs `strings` on the binary or dumps its memory sees a
// handful of strings that LOOK like plausible CTF flags:
//    ADCTF{timing_fail_abcd}
//    FLAG_DEBUG_0xDEADBEEF
//    WhipFlag{score_0_wins}
//    etc.
//
// None of these are the real flag. A solver that scrapes the binary for
// flag-looking strings, submits each, and waits for acceptance wastes
// real wall-clock time on every honeypot.
//
// Implementation
// --------------
// Strings are stored XOR-encrypted at load time with a per-string 1-byte
// key. Decryption only happens when `ad_honeypot_touch()` is called from
// main() — which forces the linker to keep the table in `.rdata` (so
// `strings` on the binary finds the ciphertext, and a memory dump during
// run finds a transient plaintext copy). Accumulating a return value the
// caller then consumes in a side-effect keeps the compiler from dead-
// stripping everything.
//
#ifndef ANTIDEBUG_FLAG_HONEYPOT_H
#define ANTIDEBUG_FLAG_HONEYPOT_H

#include "types.h"
#include "macros.h"

// Per-string XOR key. Low entropy is fine — the goal is not to hide the
// plaintext from a debugger, it's to make `strings` on the raw binary
// miss them while keeping them decryptable at runtime.
#define AD_HP_KEY  ((u8)0x5Au)

// Helper: emit a byte literal XOR-encrypted at compile time.
#define AD_HP_B(c)  ((u8)((c) ^ AD_HP_KEY))

// Encrypted honeypot flag table. Each row is a fixed-size cipher buffer
// terminated by a cipher-NUL (0 ^ key == key). The last real character
// is followed by `AD_HP_B(0)` to mark end.
//
// Row length fixed at 56 bytes to accommodate the longest plausible flag.
#define AD_HP_ROW  56u
#define AD_HP_COUNT 24u

// Each entry built inline from its plaintext. Using a static array of
// `u8` with initializer lists keeps the table fully in .rdata with no
// runtime construction.
static const u8 ad_honeypot_flags[AD_HP_COUNT][AD_HP_ROW] = {
    // 0. ADCTF{timing_fail_abcd1234}
    { AD_HP_B('A'), AD_HP_B('D'), AD_HP_B('C'), AD_HP_B('T'), AD_HP_B('F'),
      AD_HP_B('{'), AD_HP_B('t'), AD_HP_B('i'), AD_HP_B('m'), AD_HP_B('i'),
      AD_HP_B('n'), AD_HP_B('g'), AD_HP_B('_'), AD_HP_B('f'), AD_HP_B('a'),
      AD_HP_B('i'), AD_HP_B('l'), AD_HP_B('_'), AD_HP_B('a'), AD_HP_B('b'),
      AD_HP_B('c'), AD_HP_B('d'), AD_HP_B('1'), AD_HP_B('2'), AD_HP_B('3'),
      AD_HP_B('4'), AD_HP_B('}'), AD_HP_B(0) },
    // 1. FLAG{debug_0xDEADBEEF_captured}
    { AD_HP_B('F'), AD_HP_B('L'), AD_HP_B('A'), AD_HP_B('G'), AD_HP_B('{'),
      AD_HP_B('d'), AD_HP_B('e'), AD_HP_B('b'), AD_HP_B('u'), AD_HP_B('g'),
      AD_HP_B('_'), AD_HP_B('0'), AD_HP_B('x'), AD_HP_B('D'), AD_HP_B('E'),
      AD_HP_B('A'), AD_HP_B('D'), AD_HP_B('B'), AD_HP_B('E'), AD_HP_B('E'),
      AD_HP_B('F'), AD_HP_B('_'), AD_HP_B('c'), AD_HP_B('a'), AD_HP_B('p'),
      AD_HP_B('t'), AD_HP_B('u'), AD_HP_B('r'), AD_HP_B('e'), AD_HP_B('d'),
      AD_HP_B('}'), AD_HP_B(0) },
    // 2. WhipFlag{score_0_wins}
    { AD_HP_B('W'), AD_HP_B('h'), AD_HP_B('i'), AD_HP_B('p'), AD_HP_B('F'),
      AD_HP_B('l'), AD_HP_B('a'), AD_HP_B('g'), AD_HP_B('{'), AD_HP_B('s'),
      AD_HP_B('c'), AD_HP_B('o'), AD_HP_B('r'), AD_HP_B('e'), AD_HP_B('_'),
      AD_HP_B('0'), AD_HP_B('_'), AD_HP_B('w'), AD_HP_B('i'), AD_HP_B('n'),
      AD_HP_B('s'), AD_HP_B('}'), AD_HP_B(0) },
    // 3. CTF{anti_debug_bypassed_nicely}
    { AD_HP_B('C'), AD_HP_B('T'), AD_HP_B('F'), AD_HP_B('{'), AD_HP_B('a'),
      AD_HP_B('n'), AD_HP_B('t'), AD_HP_B('i'), AD_HP_B('_'), AD_HP_B('d'),
      AD_HP_B('e'), AD_HP_B('b'), AD_HP_B('u'), AD_HP_B('g'), AD_HP_B('_'),
      AD_HP_B('b'), AD_HP_B('y'), AD_HP_B('p'), AD_HP_B('a'), AD_HP_B('s'),
      AD_HP_B('s'), AD_HP_B('e'), AD_HP_B('d'), AD_HP_B('_'), AD_HP_B('n'),
      AD_HP_B('i'), AD_HP_B('c'), AD_HP_B('e'), AD_HP_B('l'), AD_HP_B('y'),
      AD_HP_B('}'), AD_HP_B(0) },
    // 4. flag{h00k_w4s_pl4c3d_4nd_w0rk3d}
    { AD_HP_B('f'), AD_HP_B('l'), AD_HP_B('a'), AD_HP_B('g'), AD_HP_B('{'),
      AD_HP_B('h'), AD_HP_B('0'), AD_HP_B('0'), AD_HP_B('k'), AD_HP_B('_'),
      AD_HP_B('w'), AD_HP_B('4'), AD_HP_B('s'), AD_HP_B('_'), AD_HP_B('p'),
      AD_HP_B('l'), AD_HP_B('4'), AD_HP_B('c'), AD_HP_B('3'), AD_HP_B('d'),
      AD_HP_B('_'), AD_HP_B('4'), AD_HP_B('n'), AD_HP_B('d'), AD_HP_B('_'),
      AD_HP_B('w'), AD_HP_B('0'), AD_HP_B('r'), AD_HP_B('k'), AD_HP_B('3'),
      AD_HP_B('d'), AD_HP_B('}'), AD_HP_B(0) },
    // 5. ADCTF{key_leaked_from_stack}
    { AD_HP_B('A'), AD_HP_B('D'), AD_HP_B('C'), AD_HP_B('T'), AD_HP_B('F'),
      AD_HP_B('{'), AD_HP_B('k'), AD_HP_B('e'), AD_HP_B('y'), AD_HP_B('_'),
      AD_HP_B('l'), AD_HP_B('e'), AD_HP_B('a'), AD_HP_B('k'), AD_HP_B('e'),
      AD_HP_B('d'), AD_HP_B('_'), AD_HP_B('f'), AD_HP_B('r'), AD_HP_B('o'),
      AD_HP_B('m'), AD_HP_B('_'), AD_HP_B('s'), AD_HP_B('t'), AD_HP_B('a'),
      AD_HP_B('c'), AD_HP_B('k'), AD_HP_B('}'), AD_HP_B(0) },
    // 6. real_flag_is_0x41414141_decoded
    { AD_HP_B('r'), AD_HP_B('e'), AD_HP_B('a'), AD_HP_B('l'), AD_HP_B('_'),
      AD_HP_B('f'), AD_HP_B('l'), AD_HP_B('a'), AD_HP_B('g'), AD_HP_B('_'),
      AD_HP_B('i'), AD_HP_B('s'), AD_HP_B('_'), AD_HP_B('0'), AD_HP_B('x'),
      AD_HP_B('4'), AD_HP_B('1'), AD_HP_B('4'), AD_HP_B('1'), AD_HP_B('4'),
      AD_HP_B('1'), AD_HP_B('4'), AD_HP_B('1'), AD_HP_B('_'), AD_HP_B('d'),
      AD_HP_B('e'), AD_HP_B('c'), AD_HP_B('o'), AD_HP_B('d'), AD_HP_B('e'),
      AD_HP_B('d'), AD_HP_B(0) },
    // 7. FLAG{th3_fl4g_w4s_h3r3_4ll_4l0ng}
    { AD_HP_B('F'), AD_HP_B('L'), AD_HP_B('A'), AD_HP_B('G'), AD_HP_B('{'),
      AD_HP_B('t'), AD_HP_B('h'), AD_HP_B('3'), AD_HP_B('_'), AD_HP_B('f'),
      AD_HP_B('l'), AD_HP_B('4'), AD_HP_B('g'), AD_HP_B('_'), AD_HP_B('w'),
      AD_HP_B('4'), AD_HP_B('s'), AD_HP_B('_'), AD_HP_B('h'), AD_HP_B('3'),
      AD_HP_B('r'), AD_HP_B('3'), AD_HP_B('_'), AD_HP_B('4'), AD_HP_B('l'),
      AD_HP_B('l'), AD_HP_B('_'), AD_HP_B('4'), AD_HP_B('l'), AD_HP_B('0'),
      AD_HP_B('n'), AD_HP_B('g'), AD_HP_B('}'), AD_HP_B(0) },
    // 8. ADCTF{vmprotect_shell_escaped}
    { AD_HP_B('A'), AD_HP_B('D'), AD_HP_B('C'), AD_HP_B('T'), AD_HP_B('F'),
      AD_HP_B('{'), AD_HP_B('v'), AD_HP_B('m'), AD_HP_B('p'), AD_HP_B('r'),
      AD_HP_B('o'), AD_HP_B('t'), AD_HP_B('e'), AD_HP_B('c'), AD_HP_B('t'),
      AD_HP_B('_'), AD_HP_B('s'), AD_HP_B('h'), AD_HP_B('e'), AD_HP_B('l'),
      AD_HP_B('l'), AD_HP_B('_'), AD_HP_B('e'), AD_HP_B('s'), AD_HP_B('c'),
      AD_HP_B('a'), AD_HP_B('p'), AD_HP_B('e'), AD_HP_B('d'), AD_HP_B('}'),
      AD_HP_B(0) },
    // 9. flag-is-this-one-for-sure
    { AD_HP_B('f'), AD_HP_B('l'), AD_HP_B('a'), AD_HP_B('g'), AD_HP_B('-'),
      AD_HP_B('i'), AD_HP_B('s'), AD_HP_B('-'), AD_HP_B('t'), AD_HP_B('h'),
      AD_HP_B('i'), AD_HP_B('s'), AD_HP_B('-'), AD_HP_B('o'), AD_HP_B('n'),
      AD_HP_B('e'), AD_HP_B('-'), AD_HP_B('f'), AD_HP_B('o'), AD_HP_B('r'),
      AD_HP_B('-'), AD_HP_B('s'), AD_HP_B('u'), AD_HP_B('r'), AD_HP_B('e'),
      AD_HP_B(0) },
    // 10. CTF{vmp_ultra_peeled_open}
    { AD_HP_B('C'), AD_HP_B('T'), AD_HP_B('F'), AD_HP_B('{'), AD_HP_B('v'),
      AD_HP_B('m'), AD_HP_B('p'), AD_HP_B('_'), AD_HP_B('u'), AD_HP_B('l'),
      AD_HP_B('t'), AD_HP_B('r'), AD_HP_B('a'), AD_HP_B('_'), AD_HP_B('p'),
      AD_HP_B('e'), AD_HP_B('e'), AD_HP_B('l'), AD_HP_B('e'), AD_HP_B('d'),
      AD_HP_B('_'), AD_HP_B('o'), AD_HP_B('p'), AD_HP_B('e'), AD_HP_B('n'),
      AD_HP_B('}'), AD_HP_B(0) },
    // 11. ADCTF{nt_syscall_hook_bypassed}
    { AD_HP_B('A'), AD_HP_B('D'), AD_HP_B('C'), AD_HP_B('T'), AD_HP_B('F'),
      AD_HP_B('{'), AD_HP_B('n'), AD_HP_B('t'), AD_HP_B('_'), AD_HP_B('s'),
      AD_HP_B('y'), AD_HP_B('s'), AD_HP_B('c'), AD_HP_B('a'), AD_HP_B('l'),
      AD_HP_B('l'), AD_HP_B('_'), AD_HP_B('h'), AD_HP_B('o'), AD_HP_B('o'),
      AD_HP_B('k'), AD_HP_B('_'), AD_HP_B('b'), AD_HP_B('y'), AD_HP_B('p'),
      AD_HP_B('a'), AD_HP_B('s'), AD_HP_B('s'), AD_HP_B('e'), AD_HP_B('d'),
      AD_HP_B('}'), AD_HP_B(0) },
    // 12. FLAG{hardware_bp_not_caught}
    { AD_HP_B('F'), AD_HP_B('L'), AD_HP_B('A'), AD_HP_B('G'), AD_HP_B('{'),
      AD_HP_B('h'), AD_HP_B('a'), AD_HP_B('r'), AD_HP_B('d'), AD_HP_B('w'),
      AD_HP_B('a'), AD_HP_B('r'), AD_HP_B('e'), AD_HP_B('_'), AD_HP_B('b'),
      AD_HP_B('p'), AD_HP_B('_'), AD_HP_B('n'), AD_HP_B('o'), AD_HP_B('t'),
      AD_HP_B('_'), AD_HP_B('c'), AD_HP_B('a'), AD_HP_B('u'), AD_HP_B('g'),
      AD_HP_B('h'), AD_HP_B('t'), AD_HP_B('}'), AD_HP_B(0) },
    // 13. ADCTF{ntdll_patched_success}
    { AD_HP_B('A'), AD_HP_B('D'), AD_HP_B('C'), AD_HP_B('T'), AD_HP_B('F'),
      AD_HP_B('{'), AD_HP_B('n'), AD_HP_B('t'), AD_HP_B('d'), AD_HP_B('l'),
      AD_HP_B('l'), AD_HP_B('_'), AD_HP_B('p'), AD_HP_B('a'), AD_HP_B('t'),
      AD_HP_B('c'), AD_HP_B('h'), AD_HP_B('e'), AD_HP_B('d'), AD_HP_B('_'),
      AD_HP_B('s'), AD_HP_B('u'), AD_HP_B('c'), AD_HP_B('c'), AD_HP_B('e'),
      AD_HP_B('s'), AD_HP_B('s'), AD_HP_B('}'), AD_HP_B(0) },
    // 14. flag{reverse_complete_1337}
    { AD_HP_B('f'), AD_HP_B('l'), AD_HP_B('a'), AD_HP_B('g'), AD_HP_B('{'),
      AD_HP_B('r'), AD_HP_B('e'), AD_HP_B('v'), AD_HP_B('e'), AD_HP_B('r'),
      AD_HP_B('s'), AD_HP_B('e'), AD_HP_B('_'), AD_HP_B('c'), AD_HP_B('o'),
      AD_HP_B('m'), AD_HP_B('p'), AD_HP_B('l'), AD_HP_B('e'), AD_HP_B('t'),
      AD_HP_B('e'), AD_HP_B('_'), AD_HP_B('1'), AD_HP_B('3'), AD_HP_B('3'),
      AD_HP_B('7'), AD_HP_B('}'), AD_HP_B(0) },
    // 15. CTF{fnv_key_rolled_back}
    { AD_HP_B('C'), AD_HP_B('T'), AD_HP_B('F'), AD_HP_B('{'), AD_HP_B('f'),
      AD_HP_B('n'), AD_HP_B('v'), AD_HP_B('_'), AD_HP_B('k'), AD_HP_B('e'),
      AD_HP_B('y'), AD_HP_B('_'), AD_HP_B('r'), AD_HP_B('o'), AD_HP_B('l'),
      AD_HP_B('l'), AD_HP_B('e'), AD_HP_B('d'), AD_HP_B('_'), AD_HP_B('b'),
      AD_HP_B('a'), AD_HP_B('c'), AD_HP_B('k'), AD_HP_B('}'), AD_HP_B(0) },
    // 16. ADCTF{veh_handler_neutered}
    { AD_HP_B('A'), AD_HP_B('D'), AD_HP_B('C'), AD_HP_B('T'), AD_HP_B('F'),
      AD_HP_B('{'), AD_HP_B('v'), AD_HP_B('e'), AD_HP_B('h'), AD_HP_B('_'),
      AD_HP_B('h'), AD_HP_B('a'), AD_HP_B('n'), AD_HP_B('d'), AD_HP_B('l'),
      AD_HP_B('e'), AD_HP_B('r'), AD_HP_B('_'), AD_HP_B('n'), AD_HP_B('e'),
      AD_HP_B('u'), AD_HP_B('t'), AD_HP_B('e'), AD_HP_B('r'), AD_HP_B('e'),
      AD_HP_B('d'), AD_HP_B('}'), AD_HP_B(0) },
    // 17. FLAG{score_forced_to_zero}
    { AD_HP_B('F'), AD_HP_B('L'), AD_HP_B('A'), AD_HP_B('G'), AD_HP_B('{'),
      AD_HP_B('s'), AD_HP_B('c'), AD_HP_B('o'), AD_HP_B('r'), AD_HP_B('e'),
      AD_HP_B('_'), AD_HP_B('f'), AD_HP_B('o'), AD_HP_B('r'), AD_HP_B('c'),
      AD_HP_B('e'), AD_HP_B('d'), AD_HP_B('_'), AD_HP_B('t'), AD_HP_B('o'),
      AD_HP_B('_'), AD_HP_B('z'), AD_HP_B('e'), AD_HP_B('r'), AD_HP_B('o'),
      AD_HP_B('}'), AD_HP_B(0) },
    // 18. DEBUG_FLAG_ENABLE_VERBOSE
    { AD_HP_B('D'), AD_HP_B('E'), AD_HP_B('B'), AD_HP_B('U'), AD_HP_B('G'),
      AD_HP_B('_'), AD_HP_B('F'), AD_HP_B('L'), AD_HP_B('A'), AD_HP_B('G'),
      AD_HP_B('_'), AD_HP_B('E'), AD_HP_B('N'), AD_HP_B('A'), AD_HP_B('B'),
      AD_HP_B('L'), AD_HP_B('E'), AD_HP_B('_'), AD_HP_B('V'), AD_HP_B('E'),
      AD_HP_B('R'), AD_HP_B('B'), AD_HP_B('O'), AD_HP_B('S'), AD_HP_B('E'),
      AD_HP_B(0) },
    // 19. flag{commitment_bypassed_ok}
    { AD_HP_B('f'), AD_HP_B('l'), AD_HP_B('a'), AD_HP_B('g'), AD_HP_B('{'),
      AD_HP_B('c'), AD_HP_B('o'), AD_HP_B('m'), AD_HP_B('m'), AD_HP_B('i'),
      AD_HP_B('t'), AD_HP_B('m'), AD_HP_B('e'), AD_HP_B('n'), AD_HP_B('t'),
      AD_HP_B('_'), AD_HP_B('b'), AD_HP_B('y'), AD_HP_B('p'), AD_HP_B('a'),
      AD_HP_B('s'), AD_HP_B('s'), AD_HP_B('e'), AD_HP_B('d'), AD_HP_B('_'),
      AD_HP_B('o'), AD_HP_B('k'), AD_HP_B('}'), AD_HP_B(0) },
    // 20. FLAG=submit_this_to_scoreboard
    { AD_HP_B('F'), AD_HP_B('L'), AD_HP_B('A'), AD_HP_B('G'), AD_HP_B('='),
      AD_HP_B('s'), AD_HP_B('u'), AD_HP_B('b'), AD_HP_B('m'), AD_HP_B('i'),
      AD_HP_B('t'), AD_HP_B('_'), AD_HP_B('t'), AD_HP_B('h'), AD_HP_B('i'),
      AD_HP_B('s'), AD_HP_B('_'), AD_HP_B('t'), AD_HP_B('o'), AD_HP_B('_'),
      AD_HP_B('s'), AD_HP_B('c'), AD_HP_B('o'), AD_HP_B('r'), AD_HP_B('e'),
      AD_HP_B('b'), AD_HP_B('o'), AD_HP_B('a'), AD_HP_B('r'), AD_HP_B('d'),
      AD_HP_B(0) },
    // 21. ADCTF{dispatcher_rerouted}
    { AD_HP_B('A'), AD_HP_B('D'), AD_HP_B('C'), AD_HP_B('T'), AD_HP_B('F'),
      AD_HP_B('{'), AD_HP_B('d'), AD_HP_B('i'), AD_HP_B('s'), AD_HP_B('p'),
      AD_HP_B('a'), AD_HP_B('t'), AD_HP_B('c'), AD_HP_B('h'), AD_HP_B('e'),
      AD_HP_B('r'), AD_HP_B('_'), AD_HP_B('r'), AD_HP_B('e'), AD_HP_B('r'),
      AD_HP_B('o'), AD_HP_B('u'), AD_HP_B('t'), AD_HP_B('e'), AD_HP_B('d'),
      AD_HP_B('}'), AD_HP_B(0) },
    // 22. win{you_found_the_real_one}
    { AD_HP_B('w'), AD_HP_B('i'), AD_HP_B('n'), AD_HP_B('{'), AD_HP_B('y'),
      AD_HP_B('o'), AD_HP_B('u'), AD_HP_B('_'), AD_HP_B('f'), AD_HP_B('o'),
      AD_HP_B('u'), AD_HP_B('n'), AD_HP_B('d'), AD_HP_B('_'), AD_HP_B('t'),
      AD_HP_B('h'), AD_HP_B('e'), AD_HP_B('_'), AD_HP_B('r'), AD_HP_B('e'),
      AD_HP_B('a'), AD_HP_B('l'), AD_HP_B('_'), AD_HP_B('o'), AD_HP_B('n'),
      AD_HP_B('e'), AD_HP_B('}'), AD_HP_B(0) },
    // 23. ADCTF{congrats_you_patched_it}
    { AD_HP_B('A'), AD_HP_B('D'), AD_HP_B('C'), AD_HP_B('T'), AD_HP_B('F'),
      AD_HP_B('{'), AD_HP_B('c'), AD_HP_B('o'), AD_HP_B('n'), AD_HP_B('g'),
      AD_HP_B('r'), AD_HP_B('a'), AD_HP_B('t'), AD_HP_B('s'), AD_HP_B('_'),
      AD_HP_B('y'), AD_HP_B('o'), AD_HP_B('u'), AD_HP_B('_'), AD_HP_B('p'),
      AD_HP_B('a'), AD_HP_B('t'), AD_HP_B('c'), AD_HP_B('h'), AD_HP_B('e'),
      AD_HP_B('d'), AD_HP_B('_'), AD_HP_B('i'), AD_HP_B('t'), AD_HP_B('}'),
      AD_HP_B(0) },
};

// ---------------------------------------------------------------------------
// Touch the honeypot table so the linker cannot strip it. Decrypt each
// row into a transient buffer and accumulate a trivial hash — the caller
// folds the return value into state the compiler cannot prove dead.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE u32 ad_honeypot_touch(void) {
    u32 acc = 0xA5A5A5A5u;
    u32 row_i, col_i;
    for (row_i = 0; row_i < AD_HP_COUNT; row_i++) {
        // Decrypt into a transient buffer on the stack so a memory scan
        // of this process briefly finds plausible flag plaintext.
        volatile u8 tmp[AD_HP_ROW];
        for (col_i = 0; col_i < AD_HP_ROW; col_i++) {
            tmp[col_i] = (u8)(ad_honeypot_flags[row_i][col_i] ^ AD_HP_KEY);
            acc = (acc * 16777619u) ^ tmp[col_i];
            if (tmp[col_i] == 0u) break;
        }
        // Do NOT wipe tmp — the goal is that a dumping reverser sees it.
        // It will go out of scope at end of iteration; the next row
        // overwrites it naturally.
    }
    return acc;
}

#endif // ANTIDEBUG_FLAG_HONEYPOT_H
