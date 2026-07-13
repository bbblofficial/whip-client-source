// ===== file: antidebug/tls_callback.c =====
//
// TLS callbacks — execute BEFORE main(), even before the CRT entry point.
//
// MSVC-specific: putting a function pointer in section .CRT$XLB causes
// the linker to thread it into the TLS callback table referenced by the
// PE TLS directory. The OS loader then invokes it on every thread
// creation/destruction event for our process — including the very first
// one, before main() runs.
//
// We do TWO things in the callback:
//   1. Mark a global so the rest of the code knows TLS ran (a debugger
//      that strips TLS leaves the marker zero).
//   2. Run a couple of cheap fast checks (PEB.BeingDebugged + a TSC
//      sample) and stash the result in another encrypted global.
//
// The main code later verifies the TLS marker AND the early-check
// result. A reverser who attaches AFTER the TLS callback ran sees the
// "debugger present" flag baked in already.
//
#ifdef _MSC_VER

#include <intrin.h>

// Public flags exposed to the rest of the project (read by extra_master).
volatile unsigned int g_ad_tls_ran            = 0;
volatile unsigned int g_ad_tls_peb_debug      = 0;
volatile unsigned long long g_ad_tls_init_tsc = 0;

// Reason codes (DLL_PROCESS_ATTACH = 1, etc.)
#define AD_DLL_PROCESS_ATTACH 1
#define AD_DLL_THREAD_ATTACH  2
#define AD_DLL_THREAD_DETACH  3
#define AD_DLL_PROCESS_DETACH 0

static void __stdcall ad_tls_callback(void* h, unsigned long reason, void* reserved) {
    (void)h; (void)reserved;

    // Mark that TLS ran. Sticky — never clear.
    g_ad_tls_ran = 0xC0DEC0DEu;

    if (reason == AD_DLL_PROCESS_ATTACH) {
        // Snapshot RDTSC at the very earliest possible moment.
        g_ad_tls_init_tsc = __rdtsc();

        // Read PEB.BeingDebugged directly via GS:0x60 → +0x02
        unsigned char* peb = (unsigned char*)__readgsqword(0x60);
        if (peb && peb[0x02]) {
            g_ad_tls_peb_debug = 1u;
        }

        // Also check NtGlobalFlag at PEB+0xBC
        if (peb) {
            unsigned int ntg = *(volatile unsigned int*)(peb + 0xBC);
            if (ntg & 0x70u) g_ad_tls_peb_debug = 1u;
        }
    }
}

// Force the linker to keep the TLS section.
#pragma section(".CRT$XLB", long, read)

__declspec(allocate(".CRT$XLB"))
void (__stdcall * const ad_tls_callback_ptr)(void*, unsigned long, void*) = ad_tls_callback;

// Reference the symbol from the include side so the linker doesn't strip it.
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:ad_tls_callback_ptr")

#endif // _MSC_VER
