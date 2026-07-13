// ===== file: antidebug/stack/stack_protect.h =====
//
// Stack-protection unified entrypoint.
//
// Wraps the per-module init plumbing (gadget table, decoy table, noise
// swarm, main-RA spoof) behind a single call so an integrating project
// can opt-in to stack spoofing with one line. Pools are built once and
// shared between flood / moonwalk / future consumers — no double scan
// of ntdll .text.
//
// Lifecycle:
//
//     ad_stack_protect_t* sp = ad_stack_protect_init(AD_SP_PROFILE_BALANCED);
//     // ... entire app ...
//     ad_stack_protect_shutdown(sp);
//
// Main return-address spoofing (`AD_SP_RA_SPOOF`) is special: it MUST run
// from the very first lines of `main()` because it overwrites the caller's
// saved RA slot via `_AddressOfReturnAddress`. Calling `ad_stack_protect_init`
// from inside main would spoof init's own frame, not main's. Use the
// `AD_STACK_PROTECT_SPOOF_MAIN()` macro at the top of main() instead.
//
#ifndef ANTIDEBUG_STACK_PROTECT_H
#define ANTIDEBUG_STACK_PROTECT_H

#include "../core/types.h"
#include "../core/macros.h"
#include "gadget_chain.h"
#include "moonwalk.h"
#include "thread_noise.h"
#include "main_ra_spoof.h"
#include "stack_flood.h"

// ---------------------------------------------------------------------------
// Init flags
// ---------------------------------------------------------------------------
#define AD_SP_NOISE_THREADS  (1u << 0)  // launch hidden noise threads
#define AD_SP_GADGET_POOL    (1u << 1)  // pre-build gadget pool from ntdll
#define AD_SP_DECOY_POOL     (1u << 2)  // pre-build decoy pool from ntdll
#define AD_SP_ALL            0xFFu

// ---------------------------------------------------------------------------
// Predefined profiles
// ---------------------------------------------------------------------------
#define AD_SP_PROFILE_LIGHT     (AD_SP_NOISE_THREADS)
#define AD_SP_PROFILE_BALANCED  (AD_SP_NOISE_THREADS | AD_SP_GADGET_POOL | AD_SP_DECOY_POOL)
#define AD_SP_PROFILE_PARANOID  AD_SP_ALL

// ---------------------------------------------------------------------------
// Internal struct — declared here for static-storage usage by callers that
// want to avoid heap. Treated as opaque: don't read fields directly.
// ---------------------------------------------------------------------------
typedef struct ad_stack_protect_s {
    u32                initialized;
    u32                flags;
    ad_gadget_table_t  gadgets;
    ad_decoy_table_t   decoys;
} ad_stack_protect_t;

// Static singleton — no allocation needed. Init writes here; shutdown clears.
ANTIDEBUG_INLINE ad_stack_protect_t* ad_stack_protect_singleton(void) {
    static ad_stack_protect_t s_sp;
    return &s_sp;
}

// ---------------------------------------------------------------------------
// Init — idempotent. Returns the singleton (never null).
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE ad_stack_protect_t* ad_stack_protect_init(u32 flags) {
    ad_stack_protect_t* sp = ad_stack_protect_singleton();
    if (sp->initialized) return sp;

    sp->flags = flags;

    if (flags & AD_SP_GADGET_POOL) {
        ad_gadget_table_init(&sp->gadgets);
    }
    if (flags & AD_SP_DECOY_POOL) {
        ad_decoy_table_init(&sp->decoys);
    }
    if (flags & AD_SP_NOISE_THREADS) {
        ad_noise_swarm_start();
    }

    sp->initialized = 1u;
    return sp;
}

// ---------------------------------------------------------------------------
// Shutdown — currently a soft tear-down: noise threads and pools live
// for the process lifetime by design (cancelling noise threads creates
// observable artifacts). We just clear the init flag so re-init is allowed.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_stack_protect_shutdown(ad_stack_protect_t* sp) {
    if (!sp) return;
    sp->initialized = 0u;
    sp->flags = 0u;
}

// ---------------------------------------------------------------------------
// Pool accessors — shared between flood / moonwalk / future consumers.
// Returns null if the corresponding flag wasn't set at init.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE const ad_gadget_table_t* ad_stack_protect_gadgets(const ad_stack_protect_t* sp) {
    if (!sp || !sp->initialized) return (const ad_gadget_table_t*)0;
    if (!(sp->flags & AD_SP_GADGET_POOL)) return (const ad_gadget_table_t*)0;
    return &sp->gadgets;
}

ANTIDEBUG_INLINE const ad_decoy_table_t* ad_stack_protect_decoys(const ad_stack_protect_t* sp) {
    if (!sp || !sp->initialized) return (const ad_decoy_table_t*)0;
    if (!(sp->flags & AD_SP_DECOY_POOL)) return (const ad_decoy_table_t*)0;
    return &sp->decoys;
}

// Convenience: pick decoy n from the singleton (returns null if unavailable).
ANTIDEBUG_INLINE void* ad_stack_protect_pick_decoy(const ad_stack_protect_t* sp, u32 n) {
    const ad_decoy_table_t* tbl = ad_stack_protect_decoys(sp);
    if (!tbl) return (void*)0;
    return ad_pick_decoy(tbl, n);
}

// ---------------------------------------------------------------------------
// Main RA spoof — must run FROM main(), not from init. Use as the very
// first statement of main(), before ad_stack_protect_init().
//
//     int main(int argc, char** argv) {
//         AD_STACK_PROTECT_SPOOF_MAIN();
//         ad_stack_protect_init(AD_SP_PROFILE_BALANCED);
//         ...
//     }
// ---------------------------------------------------------------------------
#define AD_STACK_PROTECT_SPOOF_MAIN()  ad_main_ra_spoof()

// ---------------------------------------------------------------------------
// Scope-based moonwalk RAII (C). Auto-restores RA on exit (any path).
//
//     void critical(void) {
//         AD_STACK_HIDDEN_BEGIN(sp)
//             do_sensitive_work();
//         AD_STACK_HIDDEN_END
//     }
// ---------------------------------------------------------------------------
#define AD_STACK_HIDDEN_BEGIN(sp_handle)                                      \
    do {                                                                      \
        ad_moonwalk_ctx_t _ad_mw_ctx;                                         \
        void* _ad_mw_decoy = ad_stack_protect_pick_decoy((sp_handle), 0u);    \
        ad_moonwalk_begin(&_ad_mw_ctx, _ad_mw_decoy);

#define AD_STACK_HIDDEN_END                                                   \
        ad_moonwalk_end(&_ad_mw_ctx);                                         \
    } while (0)

// ---------------------------------------------------------------------------
// ad_flood_run_protected — exception-safe stack flood (SEH).
//
//     void my_body(void* arg) { /* sensitive work */ }
//     ad_flood_run_protected(sp, my_body, &my_arg);
//
// On any exit path (return, SEH raise, /EHa C++ throw) the flood is undone.
// The flood ctx lives on the stack — fully thread-safe.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_flood_run_protected(
    struct ad_stack_protect_s* sp_handle,
    void (*body)(void*),
    void* arg
) {
    if (!body) return;
    const ad_gadget_table_t* gadgets = ad_stack_protect_gadgets(sp_handle);
    const ad_decoy_table_t*  decoys  = ad_stack_protect_decoys (sp_handle);

#if defined(_MSC_VER)
    ad_flood_ctx_t fctx;
    ad_flood_stack(&fctx, gadgets, decoys);
    __try {
        body(arg);
    }
    __finally {
        ad_flood_restore(&fctx);
    }
#else
    AD_UNUSED(gadgets); AD_UNUSED(decoys);
    body(arg);
#endif
}

#endif // ANTIDEBUG_STACK_PROTECT_H
