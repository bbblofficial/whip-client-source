// ===== file: antidebug/checks/correlation.h =====
//
// Distributed Truth Engine — correlation-based anti-debug.
//
// Concept: instead of asking "am I debugged?", we ask
// "is this environment physically possible?"
//
// Each check produces a CLAIM about the environment state.
// Claims have dependencies: if A is true, B MUST also be true.
// Contradictions between claims = exponential suspicion.
//
// A bypass must fake EVERYTHING consistently — the cost is exponential
// with the number of cross-dependencies.
//
#ifndef ANTIDEBUG_CORRELATION_H
#define ANTIDEBUG_CORRELATION_H

#include "../core/types.h"
#include "../core/macros.h"
#include "../core/value_guard.h"

// =========================================================================
// Environment state — claims from each check
// =========================================================================

// Bitfield of observed facts
typedef enum {
    AD_FACT_PEB_CLEAN         = (1u <<  0),  // PEB.BeingDebugged == 0
    AD_FACT_PEB_DEBUG         = (1u <<  1),  // PEB.BeingDebugged != 0
    AD_FACT_NTGFLAG_CLEAN     = (1u <<  2),  // NtGlobalFlag has no debug bits
    AD_FACT_NTGFLAG_DEBUG     = (1u <<  3),  // NtGlobalFlag has debug bits
    AD_FACT_HEAP_CLEAN        = (1u <<  4),  // HeapFlags normal
    AD_FACT_HEAP_DEBUG        = (1u <<  5),  // HeapFlags debug
    AD_FACT_DEBUGPORT_CLEAN   = (1u <<  6),  // ProcessDebugPort == 0
    AD_FACT_DEBUGPORT_SET     = (1u <<  7),  // ProcessDebugPort != 0
    AD_FACT_DEBUGFLAGS_CLEAN  = (1u <<  8),  // ProcessDebugFlags != 0 (NoDebugInherit set)
    AD_FACT_DEBUGFLAGS_DBG    = (1u <<  9),  // ProcessDebugFlags == 0 (debugger)
    AD_FACT_TIMING_CLEAN      = (1u << 10),  // RDTSC within normal range
    AD_FACT_TIMING_SLOW       = (1u << 11),  // RDTSC too slow (instrumentation)
    AD_FACT_SYSCALL_FAST      = (1u << 12),  // Syscall timing normal
    AD_FACT_SYSCALL_SLOW      = (1u << 13),  // Syscall timing slow (hooked)
    AD_FACT_NTDLL_CLEAN       = (1u << 14),  // ntdll stubs intact
    AD_FACT_NTDLL_HOOKED      = (1u << 15),  // ntdll stubs patched
    AD_FACT_HWBP_CLEAN        = (1u << 16),  // No hardware breakpoints
    AD_FACT_HWBP_SET          = (1u << 17),  // Hardware breakpoints active
    AD_FACT_HIDE_OK           = (1u << 18),  // ThreadHideFromDebugger succeeded + verified
    AD_FACT_HIDE_FAKED        = (1u << 19),  // ThreadHideFromDebugger returned OK but not hidden
    AD_FACT_EXCEPTION_CLEAN   = (1u << 20),  // SEH exceptions reach our handler
    AD_FACT_EXCEPTION_EATEN   = (1u << 21),  // Debugger ate our exception
    AD_FACT_PAGE_RX           = (1u << 22),  // .text is PAGE_EXECUTE_READ
    AD_FACT_PAGE_RWX          = (1u << 23),  // .text was changed to writable

    // ── Extended facts (added 2026-04-27) ──────────────────────────────
    AD_FACT_KD_ABSENT         = (1u << 24),  // KUSD.KdDebuggerEnabled == 0 AND KdDebuggerNotPresent == 1
    AD_FACT_KD_PRESENT        = (1u << 25),  // KUSD says kernel debugger attached
    AD_FACT_TOOLS_ABSENT      = (1u << 26),  // No debugger process in tasklist
    AD_FACT_TOOLS_PRESENT     = (1u << 27),  // Debugger process running (x64dbg, ida, windbg, ...)
    AD_FACT_DBGBREAK_OK       = (1u << 28),  // ntdll!DbgBreakPoint first byte == 0xCC
    AD_FACT_DBGBREAK_PATCHED  = (1u << 29),  // ntdll!DbgBreakPoint first byte != 0xCC (hooked)
} ad_fact_t;

typedef struct {
    u32 facts;              // bitmask of observed facts
    u32 contradiction_count;
} ad_truth_t;

ANTIDEBUG_INLINE void ad_truth_init(ad_truth_t* t) {
    t->facts = 0;
    t->contradiction_count = 0;
}

ANTIDEBUG_INLINE void ad_truth_set(ad_truth_t* t, ad_fact_t f) {
    t->facts |= (u32)f;
}

ANTIDEBUG_INLINE b32 ad_truth_has(const ad_truth_t* t, ad_fact_t f) {
    return (b32)((t->facts & (u32)f) != 0u);
}

// =========================================================================
// Contradiction rules — physically impossible combinations
// =========================================================================
//
// Each rule: "if FACT_A is true, FACT_B MUST NOT be true"
// Contradiction = one side was faked.

typedef struct {
    u32 if_fact;     // condition (fact that must be present)
    u32 then_not;    // fact that MUST NOT coexist with if_fact
    u32 severity;    // how impossible this combination is (1-10)
} ad_rule_t;

// The rule table — heart of the correlation engine
static const ad_rule_t g_ad_rules[] = {
    // ── PEB consistency ─────────────────────────────────────────────────
    // If NtGlobalFlag has debug bits, PEB.BeingDebugged SHOULD too
    { AD_FACT_NTGFLAG_DEBUG,   AD_FACT_PEB_CLEAN,       7 },  // NtGlobalFlag debug but PEB clean → PEB patched
    // If HeapFlags are debug, NtGlobalFlag SHOULD be too
    { AD_FACT_HEAP_DEBUG,      AD_FACT_NTGFLAG_CLEAN,   7 },  // Heap debug but NtGlobalFlag clean → NtGlobalFlag patched
    // If PEB says debug, debug port SHOULD be set
    { AD_FACT_PEB_DEBUG,       AD_FACT_DEBUGPORT_CLEAN,  5 },  // PEB debug but no debug port → inconsistent
    // All PEB clean but debug port set → stealth debugger or PEB patched
    { AD_FACT_DEBUGPORT_SET,   AD_FACT_PEB_CLEAN,        8 },

    // ── Timing vs hooks ─────────────────────────────────────────────────
    // Fast timing but slow syscalls → ntdll hooks (user-mode hooking)
    { AD_FACT_TIMING_CLEAN,    AD_FACT_SYSCALL_SLOW,     8 },
    // Fast syscalls but slow timing → hypervisor/DBI (not user-mode hooks)
    { AD_FACT_SYSCALL_FAST,    AD_FACT_TIMING_SLOW,      6 },
    // ntdll hooked but syscalls fast → impossible (hook adds latency)
    { AD_FACT_NTDLL_HOOKED,    AD_FACT_SYSCALL_FAST,     9 },

    // ── Hide thread vs debug port ───────────────────────────────────────
    // ThreadHide faked but debug port clean → sophisticated bypass
    { AD_FACT_HIDE_FAKED,      AD_FACT_DEBUGPORT_CLEAN,  9 },
    // ThreadHide OK but debug port set → kernel debugger (doesn't respect hide)
    { AD_FACT_HIDE_OK,         AD_FACT_DEBUGPORT_SET,    4 },

    // ── Exceptions vs debug ─────────────────────────────────────────────
    // Debugger eating exceptions but PEB clean → stealth debugger
    { AD_FACT_EXCEPTION_EATEN, AD_FACT_PEB_CLEAN,        8 },
    // Debugger eating exceptions but no debug port → anti-anti-debug plugin
    { AD_FACT_EXCEPTION_EATEN, AD_FACT_DEBUGPORT_CLEAN,  7 },

    // ── Code integrity vs hooks ─────────────────────────────────────────
    // .text is RWX but ntdll claims clean → someone made us writable to patch
    { AD_FACT_PAGE_RWX,        AD_FACT_NTDLL_CLEAN,      6 },
    // HW breakpoints set but PEB clean → hardware-only debugging
    { AD_FACT_HWBP_SET,        AD_FACT_PEB_CLEAN,        5 },

    // ── Extended rules (added 2026-04-27) ───────────────────────────────
    //
    // Kernel debugger present (KUSD) but PEB / DebugPort clean → kernel-mode
    // debugger that didn't attach as user-mode debugger (kd, WinDbg kernel
    // session, hypervisor inspector). Severity 9: very strong signal that
    // ScyllaHide-class user-mode hooks cannot mask (KUSD is read-only kernel
    // memory at a fixed address).
    { AD_FACT_KD_PRESENT,      AD_FACT_PEB_CLEAN,        9 },
    { AD_FACT_KD_PRESENT,      AD_FACT_DEBUGPORT_CLEAN,  8 },

    // Debugger process running but our process shows no debug signals →
    // debugger is OPEN (e.g., user has x64dbg launched alongside) without
    // being attached. Lower severity — legitimate dev box scenario — but
    // combined with other contradictions it adds up.
    { AD_FACT_TOOLS_PRESENT,   AD_FACT_PEB_CLEAN,        4 },

    // DbgBreakPoint patched (first byte != 0xCC) but PEB clean →
    // a stealth hook was applied that hides PEB but didn't hide its
    // own ntdll modification. Severity 7.
    { AD_FACT_DBGBREAK_PATCHED, AD_FACT_PEB_CLEAN,       7 },
    // DbgBreakPoint patched + ntdll claims clean → contradiction (patch IS
    // an ntdll modification by definition). Severity 8.
    { AD_FACT_DBGBREAK_PATCHED, AD_FACT_NTDLL_CLEAN,     8 },
};

#define AD_RULE_COUNT (sizeof(g_ad_rules) / sizeof(g_ad_rules[0]))

// =========================================================================
// Evaluate all contradiction rules — EXPONENTIAL scoring
// =========================================================================
//
// For N contradictions, score = 2^N (exponential growth)
// 0 contradictions = score 0 (clean)
// 1 contradiction  = score 2
// 2 contradictions = score 4
// 3 contradictions = score 8
// 6 contradictions = score 64
// 10 contradictions = score 1024

ANTIDEBUG_INLINE u32 ad_correlate(ad_truth_t* truth) {
    u32 total_severity = 0;
    u32 contradictions = 0;
    u32 i;

    for (i = 0; i < AD_RULE_COUNT; i++) {
        const ad_rule_t* rule = &g_ad_rules[i];

        // Check: if condition is met AND forbidden fact exists → contradiction
        if ((truth->facts & rule->if_fact) && (truth->facts & rule->then_not)) {
            total_severity += rule->severity;
            contradictions++;
        }
    }

    truth->contradiction_count = contradictions;

    // Exponential scoring: base severity * 2^contradictions
    // Clamped to avoid overflow
    u32 exponent = (contradictions < 16u) ? contradictions : 16u;
    u32 multiplier = 1u << exponent;

    // Final score: severity * exponential factor
    // Even small individual severities become massive with many contradictions
    return total_severity * multiplier;
}

// =========================================================================
// Populate truth from check results
// =========================================================================
//
// This is called after running all checks. It translates raw check
// results into facts, then evaluates contradictions.

// Extended variant — feeds 3 additional independent facts that ScyllaHide
// and similar PEB-only stealth shims cannot mask. Each new contradiction
// it detects also doubles the exponential multiplier on ALL existing rule
// hits, so a stealth bypass that masks PEB but leaves KUSD or ntdll prologue
// untouched gets caught with massively-amplified score.
ANTIDEBUG_INLINE u32 ad_build_truth_and_correlate_ex(
    b32 peb_debug, b32 ntgflag_debug, b32 heap_debug,
    b32 debug_port, b32 debug_flags, b32 timing_slow,
    b32 syscall_slow, b32 ntdll_hooked, b32 hwbp_set,
    b32 hide_faked, b32 exception_eaten, b32 page_rwx,
    b32 kd_present, b32 tools_present, b32 dbgbreak_patched
) {
    ad_truth_t truth;
    ad_truth_init(&truth);

    // Set complementary facts (each check produces EITHER clean OR debug)
    ad_truth_set(&truth, peb_debug     ? AD_FACT_PEB_DEBUG       : AD_FACT_PEB_CLEAN);
    ad_truth_set(&truth, ntgflag_debug ? AD_FACT_NTGFLAG_DEBUG   : AD_FACT_NTGFLAG_CLEAN);
    ad_truth_set(&truth, heap_debug    ? AD_FACT_HEAP_DEBUG      : AD_FACT_HEAP_CLEAN);
    ad_truth_set(&truth, debug_port    ? AD_FACT_DEBUGPORT_SET   : AD_FACT_DEBUGPORT_CLEAN);
    ad_truth_set(&truth, debug_flags   ? AD_FACT_DEBUGFLAGS_DBG  : AD_FACT_DEBUGFLAGS_CLEAN);
    ad_truth_set(&truth, timing_slow   ? AD_FACT_TIMING_SLOW     : AD_FACT_TIMING_CLEAN);
    ad_truth_set(&truth, syscall_slow  ? AD_FACT_SYSCALL_SLOW    : AD_FACT_SYSCALL_FAST);
    ad_truth_set(&truth, ntdll_hooked  ? AD_FACT_NTDLL_HOOKED    : AD_FACT_NTDLL_CLEAN);
    ad_truth_set(&truth, hwbp_set      ? AD_FACT_HWBP_SET        : AD_FACT_HWBP_CLEAN);
    ad_truth_set(&truth, hide_faked    ? AD_FACT_HIDE_FAKED      : AD_FACT_HIDE_OK);
    ad_truth_set(&truth, exception_eaten ? AD_FACT_EXCEPTION_EATEN : AD_FACT_EXCEPTION_CLEAN);
    ad_truth_set(&truth, page_rwx      ? AD_FACT_PAGE_RWX        : AD_FACT_PAGE_RX);

    // Extended facts
    ad_truth_set(&truth, kd_present       ? AD_FACT_KD_PRESENT       : AD_FACT_KD_ABSENT);
    ad_truth_set(&truth, tools_present    ? AD_FACT_TOOLS_PRESENT    : AD_FACT_TOOLS_ABSENT);
    ad_truth_set(&truth, dbgbreak_patched ? AD_FACT_DBGBREAK_PATCHED : AD_FACT_DBGBREAK_OK);

    return ad_correlate(&truth);
}

// Backwards-compatible shim — defaults the extended facts to "clean".
// New call sites should use `ad_build_truth_and_correlate_ex` to feed
// the new facts.
ANTIDEBUG_INLINE u32 ad_build_truth_and_correlate(
    b32 peb_debug, b32 ntgflag_debug, b32 heap_debug,
    b32 debug_port, b32 debug_flags, b32 timing_slow,
    b32 syscall_slow, b32 ntdll_hooked, b32 hwbp_set,
    b32 hide_faked, b32 exception_eaten, b32 page_rwx
) {
    return ad_build_truth_and_correlate_ex(
        peb_debug, ntgflag_debug, heap_debug,
        debug_port, debug_flags, timing_slow,
        syscall_slow, ntdll_hooked, hwbp_set,
        hide_faked, exception_eaten, page_rwx,
        /*kd_present=*/0, /*tools_present=*/0, /*dbgbreak_patched=*/0
    );
}

#endif // ANTIDEBUG_CORRELATION_H
