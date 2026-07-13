// ===== file: tests/test_uhs.c =====
//
// Universal Export Hook Scanner harness.
//   STAGE_INIT     — snapshot exports of all loaded modules
//   STAGE_CLEAN    — re-scan, expect 0 hits
//   STAGE_HOOK     — inline-hook 1 export of kernel32 (Beep or similar harmless)
//                    with a jmp rel32, verify it's detected
//   STAGE_RESTORE  — restore original bytes, expect 0 hits again
//
#include "antidebug/checks/integrity/universal_hook_scan.h"

__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int   __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) void  __stdcall OutputDebugStringA(const char*);
__declspec(dllimport) int   __stdcall VirtualProtect(void*, u64, unsigned long, unsigned long*);
__declspec(dllimport) void* __stdcall GetProcAddress(void*, const char*);
__declspec(dllimport) void* __stdcall GetModuleHandleA(const char*);
__declspec(dllimport) void* __stdcall CreateFileA(const char*, unsigned long, unsigned long, void*, unsigned long, unsigned long, void*);

static void put(const char* s) {
    int n = 0; const char* p = s;
    while (*p) { n++; p++; }
    static void* h = 0;
    if (!h) h = GetStdHandle((unsigned long)-11);
    unsigned long w = 0;
    if (h) WriteFile(h, s, (unsigned long)n, &w, 0);
    OutputDebugStringA(s);

    static void* hLog = 0;
    if (!hLog) {
        hLog = CreateFileA("C:\\temp\\uhs_result.txt",
                           0x40000000UL, 3UL, (void*)0, 2UL, 0x80UL, (void*)0);
        if (hLog == (void*)(unsigned long long)-1) hLog = 0;
    }
    if (hLog) { unsigned long lw = 0; WriteFile(hLog, s, (unsigned long)n, &lw, 0); }
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

static void u32_dec(char* out, unsigned int v) {
    char tmp[16]; int i = 0;
    if (!v) { out[0] = '0'; out[1] = 0; return; }
    while (v) { tmp[i++] = (char)('0' + (v % 10u)); v /= 10u; }
    int j; for (j = 0; j < i; j++) out[j] = tmp[i - 1 - j];
    out[i] = 0;
}

static void dump_result(const char* tag, const ad_uhs_ctx_t* ctx,
                         const ad_uhs_result_t* r) {
    put(tag);
    put("\n");
    char line[160], num[16];
    int i = 0, j;
    u32_dec(num, r->total_exports_scanned);
    const char* p = "  exports scanned : ";
    for (j = 0; p[j]; j++) line[i++] = p[j];
    for (j = 0; num[j]; j++) line[i++] = num[j];
    line[i++] = '\n'; line[i] = 0; put(line);

    i = 0;
    u32_dec(num, r->hit_count);
    const char* p2 = "  hits            : ";
    for (j = 0; p2[j]; j++) line[i++] = p2[j];
    for (j = 0; num[j]; j++) line[i++] = num[j];
    line[i++] = '\n'; line[i] = 0; put(line);

    // Enumerate hits
    u32 k;
    for (k = 0; k < r->hit_count && k < 10u; k++) {
        const ad_uhs_hit_t* h = &r->hits[k];
        const ad_uhs_module_t* M = &ctx->modules[h->module_index];
        const ad_uhs_export_t* E = &M->exports[h->export_index];
        const char* name = (const char*)(M->base + E->name_rva);

        i = 0;
        const char* pref = "    [!] ";
        for (j = 0; pref[j]; j++) line[i++] = pref[j];
        for (j = 0; j < 16 && M->name[j]; j++) line[i++] = (char)M->name[j];
        line[i++] = '!';
        for (j = 0; name[j] && j < 40; j++) line[i++] = name[j];
        while (i < 56) line[i++] = ' ';
        line[i++] = 'r'; line[i++] = '='; line[i++] = (char)('0' + (h->reason & 0xF));
        if (h->reason > 9) {
            line[i-1] = (char)('a' + (h->reason - 10));
        }
        line[i++] = ' '; line[i++] = 's'; line[i++] = '='; line[i++] = (char)('0' + (h->hook_sig & 0xF));
        line[i++] = '\n'; line[i] = 0;
        put(line);
    }
}

int main(void) {
    // Large-ish stack allocation — ctx is ~1MB. Allocate on heap via
    // static storage instead to avoid stack overflow.
    static ad_uhs_ctx_t ctx;
    int k;
    for (k = 0; k < (int)sizeof(ctx); k++)
        ((volatile unsigned char*)&ctx)[k] = 0;

    put("[UHS] === TEST START ===\n");

    if (!ad_uhs_init(&ctx)) { put("[UHS] STAGE_INIT failed\n"); return 1; }

    // Show per-module count
    char line[96], num[16];
    int i = 0, j;
    const char* pref = "[UHS] STAGE_INIT ok  modules=";
    for (j = 0; pref[j]; j++) line[i++] = pref[j];
    u32_dec(num, ctx.module_count);
    for (j = 0; num[j]; j++) line[i++] = num[j];
    line[i++] = '\n'; line[i] = 0;
    put(line);

    unsigned int m;
    for (m = 0; m < ctx.module_count; m++) {
        char l2[128]; int li = 0;
        const char* pp = "  "; for (j = 0; pp[j]; j++) l2[li++] = pp[j];
        for (j = 0; j < 16 && ctx.modules[m].name[j]; j++) l2[li++] = (char)ctx.modules[m].name[j];
        while (li < 28) l2[li++] = ' ';
        const char* px = "exports="; for (j = 0; px[j]; j++) l2[li++] = px[j];
        u32_dec(num, ctx.modules[m].export_count);
        for (j = 0; num[j]; j++) l2[li++] = num[j];
        l2[li++] = '\n'; l2[li] = 0;
        put(l2);
    }

    // STAGE_CLEAN
    ad_uhs_result_t r1;
    ad_uhs_check(&ctx, &r1);
    dump_result("[UHS] STAGE_CLEAN", &ctx, &r1);

    // STAGE_HOOK — inline hook on kernel32!Beep (rarely-called, ok to mess with)
    void* k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) { put("[UHS] cannot locate kernel32\n"); return 1; }
    unsigned char* beep = (unsigned char*)GetProcAddress(k32, "Beep");
    if (!beep) { put("[UHS] cannot find Beep\n"); return 1; }

    unsigned long old_prot = 0;
    if (VirtualProtect(beep, 16, 0x40UL, &old_prot)) {
        unsigned char saved[16];
        for (k = 0; k < 16; k++) saved[k] = beep[k];

        // Install a fake jmp rel32 (target doesn't matter; just sig)
        beep[0] = 0xE9; beep[1] = 0x00; beep[2] = 0x00; beep[3] = 0x00; beep[4] = 0x00;

        ad_uhs_result_t r2;
        ad_uhs_check(&ctx, &r2);
        dump_result("[UHS] STAGE_HOOK (Beep inline-hooked)", &ctx, &r2);

        // Restore
        for (k = 0; k < 16; k++) beep[k] = saved[k];
        unsigned long dummy = 0;
        VirtualProtect(beep, 16, old_prot, &dummy);

        ad_uhs_result_t r3;
        ad_uhs_check(&ctx, &r3);
        dump_result("[UHS] STAGE_RESTORE", &ctx, &r3);
    }

    put("[UHS] === TEST END ===\n");
    return 0;
}
