// Standalone harness for attach_detector.h.
// Build: see tests/CMakeLists.txt or compile directly with cl /std:c17 /MT.
//
// Usage:
//   1. Run test_attach_detector.exe — it prints "PID=... waiting for attach"
//      and polls every 500 ms.
//   2. From another window: x64dbg → File → Attach → pick the PID.
//   3. Within ~100-150 ms the harness prints the latched reason mask and exits.

#include <stdio.h>
#include <windows.h>
#include "antidebug/checks/runtime/attach_detector.h"

int main(void) {
    static ad_attach_ctx_t ctx;

    if (!ad_attach_detector_start(&ctx, 0u)) {
        printf("FATAL: ad_attach_detector_start failed (CreateThread or SSN resolve)\n");
        return 2;
    }

    DWORD pid = GetCurrentProcessId();
    printf("test_attach_detector  PID=%lu  waiting for attach...\n", pid);
    printf("Try: x64dbg → Attach → pick PID %lu\n\n", pid);
    fflush(stdout);

    DWORD start_tick = GetTickCount();
    DWORD last_print = 0;

    while (1) {
        u32 mask = ad_attach_was_detected(&ctx);
        if (mask) {
            DWORD elapsed = GetTickCount() - start_tick;
            printf("\n*** ATTACH DETECTED ***\n");
            printf("reason_mask = 0x%X (after %lu ms, %llu watchdog cycles)\n",
                   mask, elapsed, (unsigned long long)ctx.cycles);
            if (mask & AD_ATTACH_REASON_PEB_BD)     printf("  + PEB.BeingDebugged\n");
            if (mask & AD_ATTACH_REASON_DBG_PORT)   printf("  + ProcessDebugPort != 0\n");
            if (mask & AD_ATTACH_REASON_DBG_OBJECT) printf("  + ProcessDebugObjectHandle != NULL\n");
            if (mask & AD_ATTACH_REASON_FLAGS_FLIP) printf("  + ProcessDebugFlags flipped (NoDebugInherit not installed in this harness, ignore)\n");
            fflush(stdout);
            break;
        }

        DWORD now = GetTickCount();
        if (now - last_print >= 1000u) {
            printf(".");
            fflush(stdout);
            last_print = now;
        }
        Sleep(50);
    }

    ad_attach_detector_stop(&ctx);
    Sleep(200);  // let the watchdog observe `running=0`
    return 0;
}
