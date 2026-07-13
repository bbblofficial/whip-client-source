// ===== file: tests/test_xdp.c =====
//
// KiUserExceptionDispatcher integrity harness.
//
// STAGE_INIT  : snapshot the dispatcher bytes + hash
// STAGE_CLEAN : re-check immediately → expect mask=0
// STAGE_PATCH : self-patch the first byte → expect mask=0x01 | 0x02 (hash + jmp sig)
// STAGE_RESTORE : put original bytes back → expect mask=0
//
#include "antidebug/checks/integrity/exc_dispatcher_patch.h"

__declspec(dllimport) void  __stdcall OutputDebugStringA(const char*);
__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int   __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) int   __stdcall VirtualProtect(void*, u64, unsigned long, unsigned long*);

static void put(const char* s) {
    int n = 0; const char* p = s;
    while (*p) { n++; p++; }
    static void* h = 0;
    if (!h) h = GetStdHandle((unsigned long)-11);
    unsigned long w = 0;
    if (h) WriteFile(h, s, (unsigned long)n, &w, 0);
    OutputDebugStringA(s);
}

static void hex32(char* out, unsigned int v) {
    int i;
    out[0] = '0'; out[1] = 'x';
    for (i = 0; i < 8; i++) {
        unsigned n = (v >> ((7 - i) * 4)) & 0xF;
        out[2 + i] = (char)(n < 10 ? '0' + n : 'a' + (n - 10));
    }
    out[10] = 0;
}

static void dump_mask(const char* tag, unsigned int mask) {
    char hx[16], line[64];
    int i, j;
    hex32(hx, mask);
    for (i = 0; tag[i]; i++) line[i] = tag[i];
    line[i++] = ' '; line[i++] = 'm'; line[i++] = 'a'; line[i++] = 's'; line[i++] = 'k'; line[i++] = '=';
    for (j = 0; j < 10; j++) line[i + j] = hx[j];
    line[i + 10] = '\n'; line[i + 11] = 0;
    put(line);
}

static void dump_bytes(const char* tag, const unsigned char* b) {
    char line[96];
    int i = 0, j;
    for (j = 0; tag[j]; j++) line[i++] = tag[j];
    line[i++] = ' ';
    for (j = 0; j < (int)AD_XDP_HOOK_SIG_LEN; j++) {
        unsigned n = b[j];
        char hi = (char)((n >> 4) < 10 ? '0' + (n >> 4) : 'a' + (n >> 4) - 10);
        char lo = (char)((n & 0xF) < 10 ? '0' + (n & 0xF) : 'a' + (n & 0xF) - 10);
        line[i++] = hi; line[i++] = lo; line[i++] = ' ';
    }
    line[i++] = '\n'; line[i] = 0;
    put(line);
}

int main(void) {
    ad_xdp_ctx_t ctx;
    int k; for (k = 0; k < (int)sizeof(ctx); k++)
        ((volatile unsigned char*)&ctx)[k] = 0;

    put("[XDP] === TEST START ===\n");

    // --- stage 1: init ---
    if (!ad_xdp_init(&ctx)) {
        put("[XDP] STAGE_INIT failed\n");
        return 1;
    }
    put("[XDP] STAGE_INIT ok\n");

    {
        char hx[16], line[64];
        hex32(hx, ctx.baseline_hash);
        const char* pref = "[XDP]   baseline_hash=";
        int i, j; for (i = 0; pref[i]; i++) line[i] = pref[i];
        for (j = 0; j < 10; j++) line[i + j] = hx[j];
        line[i + 10] = '\n'; line[i + 11] = 0;
        put(line);
    }
    dump_bytes("[XDP]   baseline_bytes:", ctx.baseline_bytes);

    // --- stage 2: clean check (no patch yet) ---
    unsigned int m1 = ad_xdp_check(&ctx);
    dump_mask("[XDP] STAGE_CLEAN", m1);

    // --- stage 3: self-patch the first byte to 0xE9 (jmp rel32) ---
    // Temporarily make the page writable, flip first byte, re-check, restore.
    void* addr = ctx.dispatcher_addr;
    unsigned long old_prot = 0;
    if (VirtualProtect(addr, 16, 0x40UL /* PAGE_EXECUTE_READWRITE */, &old_prot)) {
        unsigned char orig = *(volatile unsigned char*)addr;
        *(volatile unsigned char*)addr = 0xE9;  // jmp rel32 signature

        unsigned int m2 = ad_xdp_check(&ctx);
        dump_mask("[XDP] STAGE_PATCH (jmp rel32)", m2);

        // Restore
        *(volatile unsigned char*)addr = orig;
        unsigned long dummy = 0;
        VirtualProtect(addr, 16, old_prot, &dummy);

        unsigned int m3 = ad_xdp_check(&ctx);
        dump_mask("[XDP] STAGE_RESTORE", m3);
    } else {
        put("[XDP] VirtualProtect failed — skipping self-patch stage\n");
    }

    put("[XDP] === TEST END ===\n");
    return 0;
}
