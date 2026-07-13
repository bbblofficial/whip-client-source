// ===== file: antidebug/checks/runtime/etw_ti_detect.h =====
//
// ETW-TI / process tracing detection.
//
// Distinct from etw_detect.h (which scans ntdll!EtwEventWrite for inline
// hooks). This file looks at the kernel-side trace state on the current
// process via PEB.TracingFlags. The field lives at PEB+0x320 on every
// Win10/11 build and contains a bitmask of which trace channels the
// kernel has enabled on us:
//
//   bit 0  HeapTracingEnabled
//   bit 1  CritSecTracingEnabled
//   bit 2  LibLoaderTracingEnabled
//
// EDR products that use ETW-TI (Threat-Intelligence) typically enable
// LibLoaderTracingEnabled to capture every Image_DllLoaded event coming
// out of our process. CritSec tracing is sometimes enabled by performance
// profilers (Intel VTune, ETW Insights). Heap tracing is enabled by the
// loader's own debug heap path when run under a debugger that asks for
// it.
//
// Returns 1 if ANY tracing flag is non-zero (process is being traced).
//
// Reading PEB.TracingFlags is a single MOV — no API call, no syscall,
// nothing for an EDR to filter or for ScyllaHide to wrap.
//
#ifndef ANTIDEBUG_ETW_TI_DETECT_H
#define ANTIDEBUG_ETW_TI_DETECT_H

#include "../../core/types.h"
#include "../../core/macros.h"

#define AD_PEB_TRACING_FLAGS_OFFSET   0x320

ANTIDEBUG_INLINE u32 ad_etw_ti_flags(void) {
#ifdef _MSC_VER
    u8* peb = (u8*)__readgsqword(0x60);
    if (!peb) return 0u;
    return *(volatile u32*)(peb + AD_PEB_TRACING_FLAGS_OFFSET);
#else
    return 0u;
#endif
}

ANTIDEBUG_INLINE b32 ad_etw_ti_check(void) {
    u32 flags = ad_etw_ti_flags();
    // Mask out reserved bits — only the lower three are documented.
    return (b32)((flags & 0x7u) != 0u);
}

#endif // ANTIDEBUG_ETW_TI_DETECT_H
