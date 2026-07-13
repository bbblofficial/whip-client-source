// ===== file: antidebug/syscall_bridge.cpp =====
//
// C++ implementation of the C-facing WhipSysCall bridge.
// This is the ONLY C++ file in the anti-debug framework.
//
// Exports (extern "C"):
//   whip_bridge_init()    — initialize the resolver once at startup
//   whip_bridge_resolve() — resolve an NT function name → SSN
//
// SyscallStub() is compiled from SyscallStub.asm by WhipSysCall and is
// already declared extern "C" — it links directly; no bridge wrapper needed.
//
// CMakeLists configures WHIPSYSCALL_INCLUDE so these includes just work.
//
#include "whipsyscall/SyscallResolver.h"
#include "whipsyscall/Types.h"

// C types (our framework) — included with extern "C" to avoid name-mangling
extern "C" {
    #include "core/types.h"
}

// ---------------------------------------------------------------------------
// Module-level resolver — one instance for the lifetime of the process.
// Not thread-safe by design (matches WhipSysCall's own thread-safety docs).
// ---------------------------------------------------------------------------
static SyscallResolver g_resolver;
static bool            g_initialized = false;

// ---------------------------------------------------------------------------
// C-callable exports
// ---------------------------------------------------------------------------
extern "C" {

// Initialize the WhipSysCall resolver. Call once before any check.
// Returns 1 on success, 0 on failure.
int whip_bridge_init(void) {
    if (g_initialized) return 1;
    g_initialized = g_resolver.Init();
    return g_initialized ? 1 : 0;
}

// Resolve NT function name → System Service Number.
// Returns 0xFFFF on failure (function not found or is a "fast" syscall).
u16 whip_bridge_resolve(const char* name) {
    if (!g_initialized) {
        // Auto-init on first call so callers don't have to remember to call
        // whip_bridge_init() explicitly.
        if (!g_resolver.Init()) return (u16)0xFFFF;
        g_initialized = true;
    }

    WORD  ssn  = 0;
    PVOID addr = nullptr;

    if (!g_resolver.ResolveByName(name, ssn, addr)) {
        return (u16)0xFFFF;
    }

    return (u16)ssn;
}

} // extern "C"
