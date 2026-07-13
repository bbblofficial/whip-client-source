// ===== file: tests/test_wireshark.c =====
//
// Wireshark / Npcap detection harness.
//
// Usage:
//   1. Run this exe.
//   2. It installs the real-time launch hook (SetWinEventHook worker).
//   3. Sleeps 20 seconds polling the hook flag every 500 ms.
//   4. During the sleep, launch Wireshark → the hook fires within ~50 ms
//      of Wireshark's main window taking focus.
//   5. After the sleep, prints the full aggregate state.
//
#include "antidebug/checks/runtime/wireshark_detect.h"

__declspec(dllimport) void  __stdcall OutputDebugStringA(const char*);
__declspec(dllimport) void  __stdcall Sleep(unsigned long);
__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int   __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);

static void put(const char* s) {
    int n = 0; const char* p = s;
    while (*p) { n++; p++; }
    static void* h = 0;
    if (!h) h = GetStdHandle((unsigned long)-11);
    unsigned long w = 0;
    if (h) WriteFile(h, s, (unsigned long)n, &w, 0);
    OutputDebugStringA(s);
}

int main(void) {
    // Install real-time launch hook first thing.
    b32 hook_ok = ad_ws_hook_install();
    put(hook_ok ? "[WS] hook installed (waiting for foreground-change events)\n"
                : "[WS] hook install FAILED\n");

    // Live-monitor loop — 40 iterations × 500 ms = 20 seconds.
    // During this window, start Wireshark manually to trigger the hook.
    put("[WS] 20s watch window: launch Wireshark now...\n");
    int i;
    for (i = 0; i < 40; i++) {
        Sleep(500);
        if (ad_ws_hook_triggered()) {
            put("[WS] !! HOOK FIRED — Wireshark foreground detected in real time\n");
            break;
        }
    }

    // Final snapshot across all vectors.
    b32 m  = ad_ws_module_loaded();
    b32 w  = ad_ws_window_present();
    b32 r  = ad_ws_wireshark_installed();
    b32 p  = ad_ws_process_running();
    b32 pa = ad_ws_parent_is_wireshark();
    b32 fg = ad_ws_foreground_is_wireshark();
    b32 rc = ad_ws_recent_launch();
    b32 hk = ad_ws_hook_triggered();

    put(m  ? "[WS] module wpcap/npcap loaded       : 1\n" : "[WS] module wpcap/npcap loaded       : 0\n");
    put(w  ? "[WS] window title contains Wireshark : 1\n" : "[WS] window title contains Wireshark : 0\n");
    put(r  ? "[WS] HKLM\\SOFTWARE\\Wireshark exists  : 1\n" : "[WS] HKLM\\SOFTWARE\\Wireshark exists  : 0\n");
    put(p  ? "[WS] Wireshark-family process running: 1\n" : "[WS] Wireshark-family process running: 0\n");
    put(pa ? "[WS] parent is Wireshark binary      : 1\n" : "[WS] parent is Wireshark binary      : 0\n");
    put(fg ? "[WS] foreground window is Wireshark  : 1\n" : "[WS] foreground window is Wireshark  : 0\n");
    put(rc ? "[WS] Wireshark launched < 10s ago    : 1\n" : "[WS] Wireshark launched < 10s ago    : 0\n");
    put(hk ? "[WS] real-time hook fired            : 1\n" : "[WS] real-time hook fired            : 0\n");

    u32 mask = ad_wireshark_detect();
    u32 score = ad_wireshark_score();
    char line[64]; int j = 0;
    const char* lbl = "[WS] mask=0x"; while (lbl[j]) { line[j] = lbl[j]; j++; }
    const char hex[] = "0123456789abcdef";
    line[j++] = hex[(mask >> 8) & 0xF];
    line[j++] = hex[(mask >> 4) & 0xF];
    line[j++] = hex[mask & 0xF];
    line[j++] = ' '; line[j++] = 's'; line[j++] = 'c'; line[j++] = 'o';
    line[j++] = 'r'; line[j++] = 'e'; line[j++] = '=';
    if (score >= 100) line[j++] = (char)('0' + (score / 100));
    if (score >= 10)  line[j++] = (char)('0' + ((score / 10) % 10));
    line[j++] = (char)('0' + (score % 10));
    line[j++] = '\n'; line[j] = 0;
    put(line);

    return 0;
}
