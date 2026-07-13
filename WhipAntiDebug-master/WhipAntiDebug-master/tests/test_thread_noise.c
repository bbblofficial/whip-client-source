// ===== Stealth Walk Test =====
//
// Tests ONLY the stack invisibility layer — no anti-debug checks.
// Safe to run under x64dbg without crashing.
//
//   1. Thread noise swarm (48 decoy threads)
//   2. Ghost thread execution (check runs on hidden thread)
//   3. APC execution (check runs via KiUserApcDispatcher)
//   4. Sleep window so the debugger can inspect threads + callstacks
//
#include "antidebug/core/syscall_bridge.h"
#include "antidebug/core/vmp_markers.h"
#include "antidebug/stack/thread_noise.h"
#include "antidebug/stack/stealth_exec.h"

__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int   __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) void  __stdcall Sleep(unsigned long);
__declspec(dllimport) unsigned long __stdcall GetCurrentProcessId(void);

static void print(const char* s) {
    int len = 0; const char* p = s; while (*p++) len++;
    static void* h = 0;
    if (!h) h = GetStdHandle((unsigned long)(-11));
    unsigned long w = 0;
    if (h) WriteFile(h, s, (unsigned long)len, &w, 0);
}

static void print_num(const char* label, unsigned long val) {
    char buf[64]; int bi = 0;
    while (*label) buf[bi++] = *label++;
    char num[12]; int pos = 0;
    if (val == 0) { num[pos++] = '0'; }
    else { while (val > 0) { num[pos++] = '0' + (char)(val % 10); val /= 10; } }
    int i; for (i = pos-1; i >= 0; i--) buf[bi++] = num[i];
    buf[bi++] = '\r'; buf[bi++] = '\n'; buf[bi] = 0;
    print(buf);
}

// ---------------------------------------------------------------------------
// Fake "check" functions — simulate real work without anti-debug.
// These are what a reverser would try to find in the call stack.
// ---------------------------------------------------------------------------

// Simulates a heavy check — busy loop + syscalls.
static u32 fake_heavy_check(void* arg) {
    (void)arg;
    volatile u64 acc = 0xCAFEBABEDEADBEEFULL;
    u32 i;
    for (i = 0; i < 5000u; i++) {
        acc = (acc ^ (acc >> 13)) * 0x5851F42D4C957F2DULL;
    }
    // Read PEB like a real check would
    u8* peb = (u8*)__readgsqword(0x60);
    volatile u8 bd = peb[0x02];
    (void)bd; (void)acc;
    return 42u;  // fake score
}

// Simulates a quick check — just RDTSC.
static u32 fake_quick_check(void* arg) {
    (void)arg;
    u64 t0 = __rdtsc();
    volatile u32 x = 0;
    u32 i;
    for (i = 0; i < 100u; i++) x += i;
    u64 t1 = __rdtsc();
    (void)x;
    return (u32)((t1 - t0) > 50000ULL ? 1u : 0u);
}

// Simulates a check that sleeps — like a temporal trap.
static u32 fake_temporal_check(void* arg) {
    (void)arg;
    // Small delay via busy wait
    volatile u64 waste = 0;
    u32 i;
    for (i = 0; i < 100000u; i++) waste += i;
    (void)waste;
    return 7u;
}

// ---------------------------------------------------------------------------
// Marker globals — readable in x64dbg memory view to verify results
// ---------------------------------------------------------------------------
static volatile u32 g_result_ghost  = 0xDEAD0001;
static volatile u32 g_result_apc    = 0xDEAD0002;
static volatile u32 g_result_stlth1 = 0xDEAD0003;
static volatile u32 g_result_stlth2 = 0xDEAD0004;
static volatile u32 g_result_stlth3 = 0xDEAD0005;

int main(void) {
    print("=== Stealth Walk Test ===\r\n");
    print("No anti-debug checks — safe under x64dbg.\r\n");
    print_num("PID: ", GetCurrentProcessId());

    if (!whip_bridge_init()) {
        print("[FATAL] bridge init failed\r\n");
        return 1;
    }
    print("[+] Bridge OK\r\n");

    // ── Phase 1: Thread noise swarm ────────────────────────────────────
    print("\r\n[*] Phase 1: Spawning decoy pool work items...\r\n");
    ad_noise_swarm_start();
    print("[+] Swarm active. All noise runs on ntdll pool workers — no new threads.\r\n");
    print("[*] Sleeping 5s — inspect thread list now.\r\n");
    Sleep(5000);

    // ── Phase 2: Ghost thread execution ────────────────────────────────
    print("\r\n[*] Phase 2: Ghost thread exec (heavy check)...\r\n");
    print("[*] Main thread will be in NtWaitForSingleObject.\r\n");
    g_result_ghost = ad_ghost_exec(fake_heavy_check, (void*)0);
    print_num("[+] Ghost result: ", g_result_ghost);

    print("[*] Sleeping 3s — inspect call stack now.\r\n");
    Sleep(3000);

    // ── Phase 3: APC execution ─────────────────────────────────────────
    print("\r\n[*] Phase 3: APC exec (quick check)...\r\n");
    print("[*] Callback will run via KiUserApcDispatcher.\r\n");
    g_result_apc = ad_apc_exec(fake_quick_check, (void*)0);
    print_num("[+] APC result: ", g_result_apc);

    print("[*] Sleeping 3s — inspect.\r\n");
    Sleep(3000);

    // ── Phase 4: Alternating stealth ───────────────────────────────────
    print("\r\n[*] Phase 4: Alternating stealth exec (3 checks)...\r\n");
    g_result_stlth1 = ad_stealth_exec(fake_heavy_check, (void*)0);
    print_num("[+] Stealth 1 (ghost): ", g_result_stlth1);

    g_result_stlth2 = ad_stealth_exec(fake_quick_check, (void*)0);
    print_num("[+] Stealth 2 (apc):   ", g_result_stlth2);

    g_result_stlth3 = ad_stealth_exec(fake_temporal_check, (void*)0);
    print_num("[+] Stealth 3 (ghost): ", g_result_stlth3);

    // ── Phase 5: Long sleep for deep inspection ────────────────────────
    print("\r\n[*] Phase 5: Holding 15s with swarm active.\r\n");
    print("[*] Try:\r\n");
    print("    - Thread list (should show ~4)\r\n");
    print("    - Stack walk on main thread (should show Sleep only)\r\n");
    print("    - Memory scan for 0xDEAD0001 to find result markers\r\n");
    print("    - Attach another debugger (should fail — no anti-attach here tho)\r\n");
    Sleep(15000);

    // ── Cleanup ────────────────────────────────────────────────────────
    print("\r\n[*] Killing swarm...\r\n");
    ad_noise_swarm_stop();

    print("\r\n=== Results ===\r\n");
    print_num("Ghost thread:  ", g_result_ghost);
    print_num("APC callback:  ", g_result_apc);
    print_num("Stealth 1:     ", g_result_stlth1);
    print_num("Stealth 2:     ", g_result_stlth2);
    print_num("Stealth 3:     ", g_result_stlth3);
    print("[+] All done.\r\n");
    return 0;
}
