// ===== file: antidebug/checks/runtime/heavens_gate.h =====
//
// WoW64 / Heaven's Gate guard.
//
// On a native x64 process, gs:[0x1488] (TEB.WowTebOffset) is always
// zero. On a 32-bit process running under WoW64, the field points at
// the 32-bit TEB. Reverse-engineering tools that load a native x64
// binary inside a WoW64 environment, or that use Heaven's Gate to
// trampoline between 32-bit and 64-bit modes, leave the WowTebOffset
// non-zero — which is a strong signal that the binary is not running
// in a clean native x64 process.
//
// Returns 1 if the WoW64 indicator is non-zero (hostile), 0 in clean.
//
#ifndef ANTIDEBUG_HEAVENS_GATE_H
#define ANTIDEBUG_HEAVENS_GATE_H

#include "../../core/types.h"
#include "../../core/macros.h"

ANTIDEBUG_INLINE b32 ad_heavens_gate_check(void) {
#ifdef _MSC_VER
    // TEB.WowTebOffset on x64 lives at gs:[0x1488]. The field is a
    // signed offset to the 32-bit TEB if the process runs under WoW64,
    // and exactly zero on native x64.
    u64 wow_offset = __readgsqword(0x1488);
    return (b32)(wow_offset != 0u);
#else
    return 0;
#endif
}

#endif // ANTIDEBUG_HEAVENS_GATE_H
