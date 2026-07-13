// ===== file: antidebug/checks/exceptions/veh_decoy.h =====
//
// VEH Decoy Chain.
//
// Install N vectored exception handlers. Each handler increments a
// secret counter that we encrypt-store. We then deliberately raise an
// exception we know how to handle and verify ALL N counters incremented
// in the right order.
//
// A debugger that hooks RtlAddVectoredExceptionHandler (e.g. ScyllaHide
// to suppress anti-debug VEH installs) breaks the chain — either some
// counters don't increment, or the order is wrong.
//
#ifndef ANTIDEBUG_VEH_DECOY_H
#define ANTIDEBUG_VEH_DECOY_H

#include "../../core/types.h"
#include "../../core/macros.h"

#ifdef _MSC_VER

// EXCEPTION_POINTERS / EXCEPTION_RECORD layouts (minimal)
typedef struct {
    u32  ExceptionCode;
    u32  ExceptionFlags;
    void* ExceptionRecord;
    void* ExceptionAddress;
    u32  NumberParameters;
    u32  _pad;
    u64  ExceptionInformation[15];
} AD_EXCEPTION_RECORD;

typedef struct {
    AD_EXCEPTION_RECORD* ExceptionRecord;
    void*                ContextRecord;
} AD_EXCEPTION_POINTERS;

// VEH callback type. On x64, all calls use the single x64 calling
// convention so no __stdcall annotation.
typedef long (*AD_PVECTORED_EXCEPTION_HANDLER)(AD_EXCEPTION_POINTERS*);

void* AddVectoredExceptionHandler(u32 First, AD_PVECTORED_EXCEPTION_HANDLER);
u32   RemoveVectoredExceptionHandler(void*);

#define AD_EXCEPTION_CONTINUE_SEARCH    0L
#define AD_EXCEPTION_CONTINUE_EXECUTION (-1L)

#define AD_VEH_DECOY_COUNT  4u
#define AD_VEH_MAGIC_CODE   0x57484950u  // 'WHIP'

static volatile u32 ad_veh_counter[AD_VEH_DECOY_COUNT] = {0};
static volatile u32 ad_veh_order[AD_VEH_DECOY_COUNT] = {0};
static volatile u32 ad_veh_seq = 0;

#define AD_VEH_DEFINE(idx)                                                  \
    static long ad_veh_handler_##idx(AD_EXCEPTION_POINTERS* p) {             \
        if (p && p->ExceptionRecord &&                                       \
            p->ExceptionRecord->ExceptionCode == AD_VEH_MAGIC_CODE) {        \
            ad_veh_counter[idx]++;                                           \
            ad_veh_order[idx] = ++ad_veh_seq;                                \
        }                                                                    \
        return AD_EXCEPTION_CONTINUE_SEARCH;                                 \
    }

AD_VEH_DEFINE(0)
AD_VEH_DEFINE(1)
AD_VEH_DEFINE(2)
AD_VEH_DEFINE(3)

static void* ad_veh_slots[AD_VEH_DECOY_COUNT] = {0};

ANTIDEBUG_INLINE b32 ad_veh_install(void) {
    // Install in reverse so handler 0 is called LAST (VEH is LIFO).
    ad_veh_slots[3] = AddVectoredExceptionHandler(1u, ad_veh_handler_3);
    ad_veh_slots[2] = AddVectoredExceptionHandler(1u, ad_veh_handler_2);
    ad_veh_slots[1] = AddVectoredExceptionHandler(1u, ad_veh_handler_1);
    ad_veh_slots[0] = AddVectoredExceptionHandler(1u, ad_veh_handler_0);
    u32 i;
    for (i = 0; i < AD_VEH_DECOY_COUNT; i++) {
        if (!ad_veh_slots[i]) return 0;
    }
    return 1;
}

void RaiseException(u32 dwExceptionCode, u32 dwExceptionFlags,
                    u32 nNumberOfArguments, const u64* lpArguments);

ANTIDEBUG_INLINE b32 ad_veh_check(void) {
    u32 i;
    for (i = 0; i < AD_VEH_DECOY_COUNT; i++) {
        ad_veh_counter[i] = 0;
        ad_veh_order[i] = 0;
    }
    ad_veh_seq = 0;

    __try {
        RaiseException(AD_VEH_MAGIC_CODE, 0, 0, (const u64*)0);
    }
    __except (1) {
        // We absorb it
    }

    // Verify each handler ran exactly once.
    for (i = 0; i < AD_VEH_DECOY_COUNT; i++) {
        if (ad_veh_counter[i] != 1u) return 1;
    }

    // Verify order: handler 0 ran FIRST (we installed it LAST, LIFO).
    if (ad_veh_order[0] != 1u) return 1;
    if (ad_veh_order[1] != 2u) return 1;
    if (ad_veh_order[2] != 3u) return 1;
    if (ad_veh_order[3] != 4u) return 1;

    return 0;
}

ANTIDEBUG_INLINE void ad_veh_uninstall(void) {
    u32 i;
    for (i = 0; i < AD_VEH_DECOY_COUNT; i++) {
        if (ad_veh_slots[i]) {
            RemoveVectoredExceptionHandler(ad_veh_slots[i]);
            ad_veh_slots[i] = 0;
        }
    }
}

#else
ANTIDEBUG_INLINE b32 ad_veh_install(void)   { return 0; }
ANTIDEBUG_INLINE b32 ad_veh_check(void)     { return 0; }
ANTIDEBUG_INLINE void ad_veh_uninstall(void){ }
#endif

#endif // ANTIDEBUG_VEH_DECOY_H
