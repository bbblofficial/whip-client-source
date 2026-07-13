// ===== file: boss_test.c =====
//
// Boss-test harness for the four feat/* branches landed on master:
//   - feat/anti-breakin           (DbgUiRemoteBreakin trampoline)
//   - feat/halos-gate-desync      (NtClose dual-path comparison)
//   - feat/veh-encrypted-cfg      (int3 + VEH dispatcher)
//   - feat/latent-tamper-trip     (delayed sentinel crash)
//
// Each feature is exercised in isolation. Output goes to BOTH stdout and
// OutputDebugStringA so you can read it from a regular console run, from
// the x64dbg log panel, or from DebugView.
//
// Recommended usage
// -----------------
//   1. Run standalone     -> all four checks should report PASS, the
//                            latent sentinel is intentionally NOT armed.
//   2. Open in x64dbg     -> attach BEFORE the post-init waiting window,
//                            press F9, observe DbgUiRemoteBreakin bytes
//                            patched, halos NTSTATUS divergence (0 with
//                            ScyllaHide, non-zero clean), VEH dispatched
//                            counter, etc.
//   3. Force-arm latent   -> run with --arm-latent on the command line
//                            to validate the sentinel does crash.
//
#include "antidebug/core/syscall_bridge.h"
#include "antidebug/core/api_hash.h"
#include "antidebug/checks/runtime/anti_breakin.h"
#include "antidebug/checks/runtime/halos_gate_desync.h"
#include "antidebug/checks/exceptions/veh_encrypted_cfg.h"
#include "antidebug/core/latent_tamper.h"

__declspec(dllimport) void   __stdcall OutputDebugStringA(const char* lpOutputString);
__declspec(dllimport) void*  __stdcall GetStdHandle(unsigned long nStdHandle);
__declspec(dllimport) int    __stdcall WriteFile(void* hFile, const void* lpBuffer,
                                                 unsigned long nNumberOfBytesToWrite,
                                                 unsigned long* lpNumberOfBytesWritten,
                                                 void* lpOverlapped);
__declspec(dllimport) unsigned long __stdcall GetCurrentProcessId(void);
__declspec(dllimport) void   __stdcall Sleep(unsigned long dwMilliseconds);
__declspec(dllimport) char*  __stdcall GetCommandLineA(void);

// ---------------------------------------------------------------------------
// Tiny no-CRT print helpers
// ---------------------------------------------------------------------------
static void str_append(char* dst, int* pos, const char* src) {
    while (*src && *pos < 254) { dst[(*pos)++] = *src++; }
}

static void print_raw(const char* s) {
    int len = 0;
    const char* p = s;
    while (*p++) len++;
    if (len <= 0) return;
    static void* hOut = (void*)0;
    if (!hOut) hOut = GetStdHandle((unsigned long)(-11));
    unsigned long written = 0;
    if (hOut && hOut != (void*)(unsigned long long)(-1))
        WriteFile(hOut, s, (unsigned long)len, &written, (void*)0);
    OutputDebugStringA(s);
}

static void u32_to_dec(u32 val, char* buf) {
    char tmp[12]; int n = 0;
    if (val == 0) { buf[0]='0'; buf[1]=0; return; }
    while (val > 0) { tmp[n++] = '0' + (char)(val % 10); val /= 10; }
    int i; for (i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    buf[n] = 0;
}

static void u64_to_hex(u64 val, char* buf) {
    static const char hex[] = "0123456789ABCDEF";
    int i;
    buf[0] = '0'; buf[1] = 'x';
    for (i = 0; i < 16; i++) {
        buf[2 + i] = hex[(val >> (60 - i*4)) & 0xF];
    }
    buf[18] = 0;
}

static void print_pass(const char* name) {
    char buf[256]; int pos = 0;
    str_append(buf, &pos, "[PASS] ");
    str_append(buf, &pos, name);
    str_append(buf, &pos, "\r\n");
    buf[pos] = 0;
    print_raw(buf);
}

static void print_fail(const char* name, const char* why) {
    char buf[256]; int pos = 0;
    str_append(buf, &pos, "[FAIL] ");
    str_append(buf, &pos, name);
    str_append(buf, &pos, " : ");
    str_append(buf, &pos, why);
    str_append(buf, &pos, "\r\n");
    buf[pos] = 0;
    print_raw(buf);
}

static void print_kv_u32(const char* k, u32 v) {
    char buf[128]; char num[12]; int pos = 0;
    str_append(buf, &pos, "       ");
    str_append(buf, &pos, k);
    str_append(buf, &pos, "=");
    u32_to_dec(v, num);
    str_append(buf, &pos, num);
    str_append(buf, &pos, "\r\n");
    buf[pos] = 0;
    print_raw(buf);
}

static void print_kv_hex64(const char* k, u64 v) {
    char buf[128]; char num[20]; int pos = 0;
    str_append(buf, &pos, "       ");
    str_append(buf, &pos, k);
    str_append(buf, &pos, "=");
    u64_to_hex(v, num);
    str_append(buf, &pos, num);
    str_append(buf, &pos, "\r\n");
    buf[pos] = 0;
    print_raw(buf);
}

static void section(const char* name) {
    print_raw("\r\n=== ");
    print_raw(name);
    print_raw(" ===\r\n");
}

// Tiny strstr for the --arm-latent flag.
static int contains(const char* hay, const char* needle) {
    while (*hay) {
        const char* a = hay;
        const char* b = needle;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return 1;
        hay++;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Test 1 — anti_breakin
// ---------------------------------------------------------------------------
static void test_anti_breakin(void) {
    section("test_anti_breakin");

    void* breakin = ad_resolve_api(AD_HASH_NTDLL, ad_hash_dbgui_remote_breakin());
    if (!breakin) { print_fail("anti_breakin.resolve", "DbgUiRemoteBreakin not found"); return; }
    print_kv_hex64("DbgUiRemoteBreakin", (u64)breakin);

    u8 before = *(volatile u8*)breakin;
    print_kv_u32("byte0_before", (u32)before);

    if (!ad_anti_breakin_install()) {
        print_fail("anti_breakin.install", "ad_anti_breakin_install returned 0");
        return;
    }
    u8 after = *(volatile u8*)breakin;
    print_kv_u32("byte0_after ", (u32)after);

    if (after != 0xB9) {
        print_fail("anti_breakin", "first byte is not 0xB9 after install");
        return;
    }
    if (ad_anti_breakin_verify() != 0) {
        print_fail("anti_breakin.verify", "verify reports tamper");
        return;
    }
    print_pass("anti_breakin");
}

// ---------------------------------------------------------------------------
// Test 2 — halos_gate_desync
// ---------------------------------------------------------------------------
static void test_halos_gate(void) {
    section("test_halos_gate");
    b32 tripped = ad_halos_gate_desync();
    if (tripped) {
        print_fail("halos_gate", "direct vs indirect NtClose disagreed (hook detected)");
    } else {
        print_pass("halos_gate");
    }

    u32 mask  = ad_halos_gate_multi();
    u32 count = ad_halos_gate_multi_count();
    print_kv_u32("multi_mask ", mask);
    print_kv_u32("multi_count", count);
    if (count == 0) {
        print_pass("halos_gate.multi");
    } else {
        print_fail("halos_gate.multi", "one or more syscalls hooked");
    }
}

// ---------------------------------------------------------------------------
// Test 3 — veh_encrypted_cfg
// ---------------------------------------------------------------------------
static void test_veh_cfg(void) {
    section("test_veh_cfg");
    if (!ad_veh_cfg_install()) {
        print_fail("veh_cfg.install", "RtlAddVectoredExceptionHandler resolve failed");
        return;
    }
    u32 before = ad_veh_cfg_dispatched;
    print_kv_u32("dispatched_before", before);

    b32 tripped = ad_veh_cfg_verify();
    u32 after = ad_veh_cfg_dispatched;
    print_kv_u32("dispatched_after ", after);
    print_kv_u32("delta            ", after - before);

    if (tripped) {
        print_fail("veh_cfg", "delta != 4 (debugger consumed BPs or env key non-zero)");
    } else {
        print_pass("veh_cfg");
    }
}

// ---------------------------------------------------------------------------
// Test 4 — latent_tamper
// ---------------------------------------------------------------------------
static void test_latent(int arm) {
    section("test_latent_tamper");
    if (!ad_latent_init()) {
        print_fail("latent.init", "ad_latent_init returned 0");
        return;
    }
    print_pass("latent.init");

    if (arm) {
        print_raw("       arming sentinel and sleeping 25s — process should die\r\n");
        ad_latent_arm_if(1);
        // Sleep long enough for the random delay (8-22s) to expire.
        Sleep(25000);
        print_fail("latent.fire", "main thread survived 25s post-arm — sentinel did NOT fire");
    } else {
        print_raw("       sentinel spawned but not armed — clean exit expected\r\n");
        print_pass("latent.unarmed");
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int main(void) {
    print_raw("\r\n");
    print_raw("################################################\r\n");
    print_raw("#  WhipAntiDebugger boss_test                  #\r\n");
    print_raw("#  Validates the four feat/* anti-debug layers #\r\n");
    print_raw("################################################\r\n");

    char num[12];
    u32_to_dec((u32)GetCurrentProcessId(), num);
    print_raw("PID = "); print_raw(num); print_raw("\r\n");

    print_raw("Attach window: 6 seconds — connect your debugger NOW.\r\n");
    Sleep(6000);

    if (!whip_bridge_init()) {
        print_fail("init", "whip_bridge_init failed");
        return 1;
    }
    print_pass("whip_bridge_init");

    test_anti_breakin();
    test_halos_gate();
    test_veh_cfg();

    int arm = contains(GetCommandLineA(), "--arm-latent");
    test_latent(arm);

    print_raw("\r\n=== boss_test complete ===\r\n");
    // Hold the process alive so an attached debugger can inspect the
    // patched bytes (DbgUiRemoteBreakin trampoline, VEH state, etc.).
    // 60 seconds is plenty for a manual MemoryRead and gives the latent
    // sentinel a chance to fire if --arm-latent was passed.
    print_raw("Holding 60s so a debugger can inspect the patched state.\r\n");
    Sleep(60000);
    return 0;
}
