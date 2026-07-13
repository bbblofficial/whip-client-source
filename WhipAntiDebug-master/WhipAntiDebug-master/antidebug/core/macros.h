// ===== file: antidebug/core/macros.h =====
#ifndef ANTIDEBUG_MACROS_H
#define ANTIDEBUG_MACROS_H

// ---------------------------------------------------------------------------
// MSVC intrinsics (also pulls in __rdtsc, __cpuid, __readgsqword, etc.)
// ---------------------------------------------------------------------------
#if defined(_MSC_VER)
#  include <intrin.h>
#endif

// ---------------------------------------------------------------------------
// EVEX kill switch: MSVC 14.50+ emits AVX-512 (EVEX prefix 0x62) in
// runtime-dispatched code when __isa_available >= 6. VMProtect cannot
// virtualize EVEX instructions. We clamp __isa_available to 5 (AVX2 max)
// at the very start of main() to prevent those branches from executing.
// The EVEX code still exists in the binary but is dead (never taken).
// ---------------------------------------------------------------------------
#if defined(_MSC_VER)
extern int __isa_available;
#define AD_DISABLE_AVX512() do { if (__isa_available > 5) __isa_available = 5; } while(0)
#else
#define AD_DISABLE_AVX512() ((void)0)
#endif

// ---------------------------------------------------------------------------
// Force-inline — compiler portable
// ---------------------------------------------------------------------------
#if defined(_MSC_VER)
#  define FORCEINLINE        __forceinline
#  define ANTIDEBUG_INLINE   static __forceinline
#  define NOINLINE           __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#  define FORCEINLINE        __attribute__((always_inline)) inline
#  define ANTIDEBUG_INLINE   static __attribute__((always_inline)) inline
#  define NOINLINE           __attribute__((noinline))
#else
#  define FORCEINLINE        inline
#  define ANTIDEBUG_INLINE   static inline
#  define NOINLINE
#endif

// ---------------------------------------------------------------------------
// Compiler memory / instruction barriers
// ---------------------------------------------------------------------------
#if defined(_MSC_VER)
#  define AD_BARRIER()   _ReadWriteBarrier()
#  define AD_LFENCE()    _mm_lfence()
#  define AD_MFENCE()    _mm_mfence()
#elif defined(__GNUC__) || defined(__clang__)
#  define AD_BARRIER()   __asm__ __volatile__("" ::: "memory")
#  define AD_LFENCE()    __asm__ __volatile__("lfence" ::: "memory")
#  define AD_MFENCE()    __asm__ __volatile__("mfence" ::: "memory")
#else
#  define AD_BARRIER()   ((void)0)
#  define AD_LFENCE()    ((void)0)
#  define AD_MFENCE()    ((void)0)
#endif

// ---------------------------------------------------------------------------
// Branch-prediction hints (mirrors VM_LIKELY/VM_UNLIKELY in vm_interp.h,
// usable project-wide without pulling in the VM header)
// ---------------------------------------------------------------------------
#if defined(__GNUC__) || defined(__clang__)
#  define AD_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define AD_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#  define AD_LIKELY(x)   (x)
#  define AD_UNLIKELY(x) (x)
#endif

// ---------------------------------------------------------------------------
// Suppress unused-variable warnings
// ---------------------------------------------------------------------------
#define AD_UNUSED(x)  ((void)(x))

// ---------------------------------------------------------------------------
// Volatile read — prevent optimizer from eliminating a check result.
// Use cast-through-volatile-pointer; avoids __typeof__ (MSVC C incompatible).
// ---------------------------------------------------------------------------
#define AD_VOLATILE_READ_U32(x)  (*(volatile unsigned int*)&(x))
#define AD_VOLATILE_READ_U64(x)  (*(volatile unsigned long long*)&(x))

// ---------------------------------------------------------------------------
// Zero a small stack buffer without memset
// ---------------------------------------------------------------------------
#define AD_ZERO_BUF(buf, size)              \
    do {                                    \
        volatile unsigned char* _p =        \
            (volatile unsigned char*)(buf); \
        unsigned int _i = 0;               \
        for (_i = 0; _i < (size); _i++)    \
            _p[_i] = 0;                    \
    } while(0)

#endif // ANTIDEBUG_MACROS_H
