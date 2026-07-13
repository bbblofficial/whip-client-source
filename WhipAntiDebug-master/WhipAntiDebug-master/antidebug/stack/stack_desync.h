// ===== file: antidebug/stack/stack_desync.h =====
//
// Stack desynchronization — confuse debugger stack walkers.
//
// Techniques:
//
//   1. Frame Pointer Poison:
//      Write a fake RBP chain that loops back on itself. x64dbg's stack
//      walker follows RBP→saved_RBP→... and enters an infinite loop or
//      shows garbage frames. Our code doesn't use frame pointers (/Oy)
//      so this doesn't affect execution.
//
//   2. Shadow Space Pollution:
//      The x64 calling convention mandates 32 bytes of shadow space above
//      each CALL's return address. Debuggers often peek at shadow space
//      for parameter recovery. We fill it with decoy values that look
//      like valid addresses (ntdll pointers) to mislead analysis.
//
//   3. Return Address Scramble:
//      Temporarily XOR all return addresses on the stack with a key,
//      execute sensitive code, then unscramble. If a debugger reads the
//      stack during execution, it sees encrypted gibberish.
//
#ifndef ANTIDEBUG_STACK_DESYNC_H
#define ANTIDEBUG_STACK_DESYNC_H

#include "../core/types.h"
#include "../core/macros.h"

#if defined(_MSC_VER)
#include <intrin.h>
#endif

// ---------------------------------------------------------------------------
// Shadow space pollution — fill caller's shadow with ntdll decoys
//
// The shadow space is at [RSP+8..RSP+28] after a CALL. We write decoy
// addresses there so the debugger's parameter analysis is wrong.
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_pollute_shadow(void** decoys, u32 count) {
#if defined(_MSC_VER)
    // Shadow space of OUR caller is at _AddressOfReturnAddress() + 8
    void** shadow = (void**)((u8*)_AddressOfReturnAddress() + sizeof(void*));

    u32 i;
    u32 max_slots = (count < 4u) ? count : 4u;  // shadow is 4 slots
    for (i = 0; i < max_slots; i++) {
        if (decoys && decoys[i]) {
            shadow[i] = decoys[i];
        }
    }
#else
    AD_UNUSED(decoys);
    AD_UNUSED(count);
#endif
}

// ---------------------------------------------------------------------------
// Return address scramble/unscramble
//
// Walk the stack via RBP chain and XOR each return address with a key.
// Call _scramble before sensitive work, _unscramble after.
//
// WARNING: requires frame pointers (/Oy-). With FPO, this is a no-op.
// ---------------------------------------------------------------------------
typedef struct {
    u64 key;
    u32 depth;
} ad_stack_scramble_ctx_t;

ANTIDEBUG_INLINE void ad_stack_scramble(ad_stack_scramble_ctx_t* ctx, u32 depth) {
#if defined(_MSC_VER)
    // Generate a per-call key from RDTSC
    u64 key = __rdtsc();
    key ^= (key << 13);
    key ^= (key >> 7);
    key |= 1ULL;  // ensure non-zero

    ctx->key   = key;
    ctx->depth = 0;

    // Walk frames via RBP chain
    u8* fp = (u8*)_AddressOfReturnAddress() - sizeof(void*);

    u32 i;
    for (i = 0; i < depth && i < 8u; i++) {
        void** ret_slot = (void**)(fp + sizeof(void*));
        u64 original = (u64)(unsigned long long)*ret_slot;

        // XOR the return address
        *ret_slot = (void*)(unsigned long long)(original ^ key);
        ctx->depth++;

        // Walk to parent frame
        u8* parent = *(u8**)fp;
        if (!parent || parent <= fp) break;
        fp = parent;
    }
#else
    AD_UNUSED(ctx);
    AD_UNUSED(depth);
#endif
}

ANTIDEBUG_INLINE void ad_stack_unscramble(ad_stack_scramble_ctx_t* ctx) {
#if defined(_MSC_VER)
    if (ctx->depth == 0 || ctx->key == 0) return;

    u8* fp = (u8*)_AddressOfReturnAddress() - sizeof(void*);

    u32 i;
    for (i = 0; i < ctx->depth; i++) {
        void** ret_slot = (void**)(fp + sizeof(void*));
        u64 scrambled = (u64)(unsigned long long)*ret_slot;

        // Un-XOR
        *ret_slot = (void*)(unsigned long long)(scrambled ^ ctx->key);

        u8* parent = *(u8**)fp;
        if (!parent || parent <= fp) break;
        fp = parent;
    }

    ctx->key   = 0;
    ctx->depth = 0;
#else
    AD_UNUSED(ctx);
#endif
}

// ---------------------------------------------------------------------------
// Convenience: execute a function with scrambled stack
// ---------------------------------------------------------------------------
ANTIDEBUG_INLINE void ad_scrambled_call(
    void (*fn)(void* arg),
    void*  arg,
    u32    depth
) {
    ad_stack_scramble_ctx_t ctx;
    ad_stack_scramble(&ctx, depth);
    fn(arg);
    ad_stack_unscramble(&ctx);
}

#endif // ANTIDEBUG_STACK_DESYNC_H
