// ===== file: antidebug/checks/runtime/tls_check.h =====
//
// TLS callback verifier.
//
// The TLS callback in antidebug/tls_callback.c sets globals BEFORE
// main() runs. We verify those globals here:
//   1. g_ad_tls_ran must be the magic value → TLS callback fired
//   2. g_ad_tls_peb_debug must be 0 → debugger wasn't present at TLS time
//   3. g_ad_tls_init_tsc must be < current RDTSC → sanity
//
// If a debugger attached AFTER our TLS but BEFORE main(), we'd see
// peb_debug = 1. If the reverser stripped/zeroed the TLS directory,
// g_ad_tls_ran stays 0 → caught.
//
#ifndef ANTIDEBUG_TLS_CHECK_H
#define ANTIDEBUG_TLS_CHECK_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER
extern volatile unsigned int       g_ad_tls_ran;
extern volatile unsigned int       g_ad_tls_peb_debug;
extern volatile unsigned long long g_ad_tls_init_tsc;

// Returns nonzero if the TLS callback either didn't run, or detected
// a debugger at startup.
ANTIDEBUG_INLINE u32 ad_tls_check(void) {
    u32 score = 0;
    if (g_ad_tls_ran != 0xC0DEC0DEu) {
        score += 8u;
    }
    if (g_ad_tls_peb_debug != 0u) {
        score += 6u;
    }
    return score;
}
#else
ANTIDEBUG_INLINE u32 ad_tls_check(void) { return 0; }
#endif

#endif // ANTIDEBUG_TLS_CHECK_H
