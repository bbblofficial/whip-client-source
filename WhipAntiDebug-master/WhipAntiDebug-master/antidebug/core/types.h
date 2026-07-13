// ===== file: antidebug/core/types.h =====
#ifndef ANTIDEBUG_TYPES_H
#define ANTIDEBUG_TYPES_H

// ---------------------------------------------------------------------------
// Primitive types — uses <stdint.h> exact-width types so external projects
// that define `u32 = uint32_t` (etc.) interoperate without C2371 redefinition
// errors. On x64 Windows `unsigned long` and `unsigned int` are both 32-bit
// but distinct types per the C++ standard, which broke header sharing.
// ---------------------------------------------------------------------------
#include <stdint.h>

typedef uint8_t            u8;
typedef uint16_t           u16;
typedef uint32_t           u32;
typedef uint64_t           u64;
typedef int8_t             s8;
typedef int16_t            s16;
typedef int32_t            s32;
typedef int64_t            s64;
typedef int                b32;   // boolean (0 false, nonzero true)
typedef void*              ad_handle_t;
typedef long               ad_ntstatus_t;  // matches Windows NTSTATUS (LONG)

// ---------------------------------------------------------------------------
// NT pseudo-handles (no WinAPI import)
// ---------------------------------------------------------------------------
#define AD_CURRENT_PROCESS ((ad_handle_t)(s64)(-1))
#define AD_CURRENT_THREAD  ((ad_handle_t)(s64)(-2))

// ---------------------------------------------------------------------------
// NT status
// ---------------------------------------------------------------------------
#define AD_NT_SUCCESS(s)   ((ad_ntstatus_t)(s) >= 0)
#define AD_STATUS_SUCCESS  ((ad_ntstatus_t)0x00000000L)

// ---------------------------------------------------------------------------
// Process / Thread information classes
// ---------------------------------------------------------------------------
#define AD_PROCESS_DEBUG_PORT          7
#define AD_PROCESS_DEBUG_OBJECT_HANDLE 30
#define AD_PROCESS_DEBUG_FLAGS         31

#define AD_THREAD_HIDE_FROM_DEBUGGER   17

// ---------------------------------------------------------------------------
// CONTEXT flags
// ---------------------------------------------------------------------------
#define AD_CONTEXT_AMD64              0x00100000UL
#define AD_CONTEXT_DEBUG_REGISTERS    (AD_CONTEXT_AMD64 | 0x00000010UL)

// ---------------------------------------------------------------------------
// Heap / NtGlobalFlag debug markers
// ---------------------------------------------------------------------------
#define AD_FLG_HEAP_ENABLE_TAIL_CHECK    0x10UL
#define AD_FLG_HEAP_ENABLE_FREE_CHECK    0x20UL
#define AD_FLG_HEAP_VALIDATE_PARAMETERS  0x40UL
#define AD_HEAP_DEBUG_FLAGS \
    (AD_FLG_HEAP_ENABLE_TAIL_CHECK | \
     AD_FLG_HEAP_ENABLE_FREE_CHECK | \
     AD_FLG_HEAP_VALIDATE_PARAMETERS)

// ---------------------------------------------------------------------------
// Alignment helper — MSVC / GCC portable
// ---------------------------------------------------------------------------
#if defined(_MSC_VER)
#  define AD_ALIGN(n) __declspec(align(n))
#else
#  define AD_ALIGN(n) __attribute__((aligned(n)))
#endif

// ---------------------------------------------------------------------------
// x64 CONTEXT structure (manually defined — no winnt.h import required)
// Full size: 0x4D0 bytes, must be 16-byte aligned.
// ---------------------------------------------------------------------------
typedef struct AD_ALIGN(16) _AD_CONTEXT {
    // Home addresses (shadow space for callee)
    u64 P1Home;           // 0x000
    u64 P2Home;           // 0x008
    u64 P3Home;           // 0x010
    u64 P4Home;           // 0x018
    u64 P5Home;           // 0x020
    u64 P6Home;           // 0x028

    // Control
    u32 ContextFlags;     // 0x030
    u32 MxCsr;            // 0x034

    // Segments
    u16 SegCs;            // 0x038
    u16 SegDs;            // 0x03A
    u16 SegEs;            // 0x03C
    u16 SegFs;            // 0x03E
    u16 SegGs;            // 0x040
    u16 SegSs;            // 0x042
    u32 EFlags;           // 0x044

    // Debug registers
    u64 Dr0;              // 0x048
    u64 Dr1;              // 0x050
    u64 Dr2;              // 0x058
    u64 Dr3;              // 0x060
    u64 Dr6;              // 0x068
    u64 Dr7;              // 0x070

    // Integer registers
    u64 Rax;              // 0x078
    u64 Rcx;              // 0x080
    u64 Rdx;              // 0x088
    u64 Rbx;              // 0x090
    u64 Rsp;              // 0x098
    u64 Rbp;              // 0x0A0
    u64 Rsi;              // 0x0A8
    u64 Rdi;              // 0x0B0
    u64 R8;               // 0x0B8
    u64 R9;               // 0x0C0
    u64 R10;              // 0x0C8
    u64 R11;              // 0x0D0
    u64 R12;              // 0x0D8
    u64 R13;              // 0x0E0
    u64 R14;              // 0x0E8
    u64 R15;              // 0x0F0
    u64 Rip;              // 0x0F8

    // FPU / XMM / YMM / debug branch records — pad to 0x4D0
    u8  _flt_xmm_rest[0x4D0 - 0x100];
} AD_CONTEXT;

// Compile-time size assertion (C11+)
#ifdef __STDC_VERSION__
#  if __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(AD_CONTEXT) == 0x4D0, "AD_CONTEXT size mismatch");
#  endif
#endif

// ---------------------------------------------------------------------------
// NT object structures — used across multiple checks
// ---------------------------------------------------------------------------
#ifndef AD_OBJECT_ATTRIBUTES_DEFINED
#define AD_OBJECT_ATTRIBUTES_DEFINED
typedef struct {
    u32         Length;
    ad_handle_t RootDirectory;
    void*       ObjectName;
    u32         Attributes;
    ad_handle_t SecurityDescriptor;
    ad_handle_t SecurityQualityOfService;
} AD_OBJECT_ATTRIBUTES;
#endif

#ifndef AD_CLIENT_ID_DEFINED
#define AD_CLIENT_ID_DEFINED
typedef struct {
    void* UniqueProcess;    // Process ID (cast to pointer-sized integer)
    void* UniqueThread;     // Thread ID (NULL for NtOpenProcess)
} AD_CLIENT_ID;
#endif

// ---------------------------------------------------------------------------
// PROCESS_BASIC_INFORMATION (NtQueryInformationProcess class 0)
// ---------------------------------------------------------------------------
typedef struct _AD_PROCESS_BASIC_INFO {
    ad_ntstatus_t ExitStatus;
    void*         PebBaseAddress;
    void*         AffinityMask;
    s32           BasePriority;
    s32           _pad0;
    void*         UniqueProcessId;
    void*         InheritedFromUniqueProcessId;
} AD_PROCESS_BASIC_INFO;

// ---------------------------------------------------------------------------
// Result of one ad_run() call — defined here so mem_encrypt.h can reference it
// ---------------------------------------------------------------------------
typedef struct {
    u32 score;         // Composite suspicion score (nonzero = suspicious)
    u32 checks_run;    // How many checks executed this call
    u32 checks_hit;    // How many fired (returned suspicious)
    u32 check_mask;    // Bitmask: bit N = check N fired (up to 32 checks)
    u32 _transit_key;  // XOR key for score transit encryption (use AD_DECRYPT_RESULT)
} ad_result_t;

#endif // ANTIDEBUG_TYPES_H
