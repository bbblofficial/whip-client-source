// ===== file: tests/test_btb_triangulate.c =====
//
// BTB triangulation check harness.
//
// STAGE_CLEAN       : check on pristine table → expect 0
// STAGE_SLOW_GADGET : patch gadget[5] in place with an artificial slow loop
//                     (~2000 cycles) to simulate the latency blow-up that a
//                     #DB roundtrip or debugger-intercepted HWBP produces.
//                     Expect 1 (outlier detection path).
// STAGE_POST_RESTORE: restore original gadget, expect 0 again.
// STAGE_X64DBG      : 15s pause so the user can attach x64dbg, set a real
//                     HW-exec BP on any printed gadget address, resume.
//                     Expect 1.
//
// Note on self-test via SetThreadContext: on Windows 10/11 a user-mode
// process can WRITE to the DR registers of its own thread via
// SetThreadContext, and GetThreadContext reads them back, but the CPU's
// actual DR regs are not loaded unless a kernel debugger or user-mode
// debug port is attached. So a self-armed HWBP never fires #DB. The
// slow-gadget patch below validates the same outlier detection path
// that a real HWBP triggers under a debugger.
//
#include "antidebug/checks/advanced/btb_triangulate.h"

__declspec(dllimport) void  __stdcall OutputDebugStringA(const char* s);
__declspec(dllimport) void  __stdcall Sleep(unsigned long ms);
__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long nStdHandle);
__declspec(dllimport) int   __stdcall WriteFile(void* hFile, const void* buf,
                                                 unsigned long n,
                                                 unsigned long* written,
                                                 void* overlapped);

static void put(const char* s) {
    int len = 0; const char* p = s;
    while (*p) { len++; p++; }
    static void* h = 0;
    if (!h) h = GetStdHandle((unsigned long)-11);
    unsigned long w = 0;
    if (h) WriteFile(h, s, (unsigned long)len, &w, 0);
    OutputDebugStringA(s);
}

static void hex64(char* out, unsigned long long v) {
    int i;
    out[0] = '0'; out[1] = 'x';
    for (i = 0; i < 16; i++) {
        unsigned n = (unsigned)((v >> ((15 - i) * 4)) & 0xF);
        out[2 + i] = (char)(n < 10 ? '0' + n : 'a' + (n - 10));
    }
    out[18] = 0;
}

// Slow gadget body, 16 bytes, same layout as AD_BTB_GADGET_BYTES:
//   endbr64                  F3 0F 1E FA
//   mov   ecx, 0x400         B9 00 04 00 00
//   dec   ecx                FF C9
//   jnz   -4                 75 FC
//   xor   eax, eax           31 C0
//   ret                      C3
// ~2048 cycles per call (1024 iter × ~2 cycles). Simulates HWBP roundtrip.
static const unsigned char SLOW_GADGET[16] = {
    0xF3, 0x0F, 0x1E, 0xFA,
    0xB9, 0x00, 0x04, 0x00, 0x00,
    0xFF, 0xC9,
    0x75, 0xFC,
    0x31, 0xC0,
    0xC3
};

static void dump_lats(const char* tag, u64* lats) {
    char hx[32], line[96];
    int i, j, k;
    int tlen = 0; while (tag[tlen]) tlen++;
    put(tag);
    put("\n");
    for (i = 0; i < (int)AD_BTB_GADGETS; i++) {
        hex64(hx, lats[i]);
        line[0] = ' '; line[1] = ' '; line[2] = 'l';
        line[3] = (char)('0' + (i / 10));
        line[4] = (char)('0' + (i % 10));
        line[5] = '=';
        for (j = 0, k = 6; j < 18; j++, k++) line[k] = hx[j];
        line[k++] = '\n'; line[k] = 0;
        put(line);
    }
}

int main(void) {
    char hx[32], line[160];
    int  i, j;
    u64  lats[AD_BTB_GADGETS];

    // Shared state used by the whole harness — one RWX page, one table.
    static ad_btb_state_t st = {0};

    // --- stage 1: clean ---
    b32 r1 = ad_btb_triangulate_check_ex(&st);

    put("[BTB] gadget table:\n");
    for (i = 0; i < (int)AD_BTB_GADGETS; i++) {
        hex64(hx, (unsigned long long)(unsigned __int64)st.targets[i]);
        line[0] = ' '; line[1] = ' '; line[2] = 'g';
        line[3] = (char)('0' + (i / 10)); line[4] = (char)('0' + (i % 10));
        line[5] = '=';
        for (j = 0; j < 18; j++) line[6 + j] = hx[j];
        line[24] = '\n'; line[25] = 0;
        put(line);
    }
    put(r1 ? "[BTB] STAGE_CLEAN        result=1 (UNEXPECTED)\n"
           : "[BTB] STAGE_CLEAN        result=0 (OK)\n");

    ad_btb_triangulate_lats(&st, lats);
    dump_lats("[BTB] clean latencies:", lats);

    // --- stage 2: patch gadget[5] with a slow body in place ---
    volatile unsigned char* g5 = (volatile unsigned char*)st.targets[5];
    unsigned char backup[16];
    for (i = 0; i < 16; i++) backup[i] = g5[i];
    for (i = 0; i < 16; i++) g5[i] = SLOW_GADGET[i];

    ad_btb_triangulate_lats(&st, lats);
    dump_lats("[BTB] patched latencies (gadget[5] should spike):", lats);

    b32 r2 = ad_btb_triangulate_check_ex(&st);
    put(r2 ? "[BTB] STAGE_SLOW_GADGET  result=1 (DETECTED — OK)\n"
           : "[BTB] STAGE_SLOW_GADGET  result=0 (MISS)\n");

    // --- stage 3: restore ---
    for (i = 0; i < 16; i++) g5[i] = backup[i];

    b32 r3 = ad_btb_triangulate_check_ex(&st);
    put(r3 ? "[BTB] STAGE_POST_RESTORE result=1 (unexpected false pos)\n"
           : "[BTB] STAGE_POST_RESTORE result=0 (OK)\n");

    // --- stage 4: x64dbg manual test ---
    put("[BTB] sleeping 15s — in x64dbg, set a HW-exec BP on any gadget addr above, then F9.\n");
    Sleep(15000);

    b32 r4 = ad_btb_triangulate_check_ex(&st);
    put(r4 ? "[BTB] STAGE_X64DBG       result=1 (DETECTED)\n"
           : "[BTB] STAGE_X64DBG       result=0 (no HWBP set, or missed)\n");

    Sleep(1500);
    return 0;
}
