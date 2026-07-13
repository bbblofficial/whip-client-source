// ===== file: tests/test_sdm.c =====
//
// Self disk-vs-memory integrity harness.
//   STAGE_INIT    — locate our own .text
//   STAGE_CLEAN   — compare disk vs memory, expect mask=0
//   STAGE_PATCH   — self-patch one byte in our .text, expect mask bit set
//   STAGE_RESTORE — put original byte back, expect mask=0
//
#include "antidebug/checks/integrity/self_disk_mem.h"

__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int   __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) void  __stdcall OutputDebugStringA(const char*);
__declspec(dllimport) int   __stdcall VirtualProtect(void*, u64, unsigned long, unsigned long*);
__declspec(dllimport) void* __stdcall VirtualAlloc(void*, u64, unsigned long, unsigned long);

static void put(const char* s) {
    int n = 0; const char* p = s;
    while (*p) { n++; p++; }
    static void* h = 0;
    if (!h) h = GetStdHandle((unsigned long)-11);
    unsigned long w = 0;
    if (h) WriteFile(h, s, (unsigned long)n, &w, 0);
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

static void u32_dec(char* out, unsigned int v) {
    char tmp[16]; int i = 0;
    if (!v) { out[0] = '0'; out[1] = 0; return; }
    while (v) { tmp[i++] = (char)('0' + (v % 10u)); v /= 10u; }
    int j; for (j = 0; j < i; j++) out[j] = tmp[i - 1 - j];
    out[i] = 0;
}

static void dump_mask(const char* tag, unsigned long long mask) {
    char hx[32], line[128];
    hex64(hx, mask);
    int i = 0, j;
    for (j = 0; tag[j]; j++) line[i++] = tag[j];
    line[i++] = ' '; line[i++] = 'm'; line[i++] = 'a'; line[i++] = 's'; line[i++] = 'k'; line[i++] = '=';
    for (j = 0; j < 18; j++) line[i + j] = hx[j];
    line[i + 18] = '\n'; line[i + 19] = 0;
    put(line);

    for (j = 0; j < (int)AD_SDM_CHUNK_COUNT; j++) {
        if (mask & (1ULL << j)) {
            char out[32], num[8];
            u32_dec(num, (unsigned)j);
            const char* p = "    [!] chunk ";
            int ii = 0, k;
            for (k = 0; p[k]; k++) out[ii++] = p[k];
            for (k = 0; num[k]; k++) out[ii++] = num[k];
            out[ii++] = ' '; out[ii++] = 'd'; out[ii++] = 'i'; out[ii++] = 'f';
            out[ii++] = 'f'; out[ii++] = 'e'; out[ii++] = 'r'; out[ii++] = 's';
            out[ii++] = '\n'; out[ii] = 0;
            put(out);
        }
    }
}

int main(void) {
    ad_sdm_ctx_t ctx;
    int k;
    for (k = 0; k < (int)sizeof(ctx); k++)
        ((volatile unsigned char*)&ctx)[k] = 0;

    put("[SDM] === TEST START ===\n");

    if (!ad_sdm_init(&ctx)) {
        put("[SDM] STAGE_INIT failed\n");
        return 1;
    }

    {
        char hx[32], line[128], num[16];
        int i = 0, j;
        const char* p1 = "[SDM] STAGE_INIT ok  .text mem@";
        for (j = 0; p1[j]; j++) line[i++] = p1[j];
        hex64(hx, (unsigned long long)(unsigned __int64)ctx.text_base_mem);
        for (j = 0; j < 18; j++) line[i + j] = hx[j];
        i += 18;
        const char* p2 = "  size=";
        for (j = 0; p2[j]; j++) line[i++] = p2[j];
        u32_dec(num, ctx.text_size);
        for (j = 0; num[j]; j++) line[i++] = num[j];
        const char* p3 = " bytes, disk_off=";
        for (j = 0; p3[j]; j++) line[i++] = p3[j];
        u32_dec(num, ctx.text_disk_offset);
        for (j = 0; num[j]; j++) line[i++] = num[j];
        const char* p4 = ", chunks=";
        for (j = 0; p4[j]; j++) line[i++] = p4[j];
        u32_dec(num, ctx.chunk_count);
        for (j = 0; num[j]; j++) line[i++] = num[j];
        line[i++] = '\n'; line[i] = 0;
        put(line);
    }

    // Allocate scratch buffer to hold disk bytes (size = text_size rounded up)
    u32 buf_size = ctx.text_size + 0x1000u;
    u8* scratch = (u8*)VirtualAlloc((void*)0, buf_size, 0x3000u, 0x04u);
    if (!scratch) {
        put("[SDM] scratch alloc failed\n");
        return 1;
    }

    // STAGE_CLEAN
    dump_mask("[SDM] STAGE_CLEAN", ad_sdm_check(&ctx, scratch, buf_size));

    // STAGE_PATCH — flip a byte deep in .text (avoid first bytes which hold
    // the prologue of put(), called next). Use 3/4 of the way through so
    // the patched byte is inside a function we don't invoke between the
    // patch and the restore.
    u8* patch_target = ctx.text_base_mem + (ctx.text_size * 3u) / 4u;
    unsigned long old_prot = 0;
    if (VirtualProtect(patch_target, 16, 0x40UL, &old_prot)) {
        unsigned char orig = *(volatile unsigned char*)patch_target;
        *(volatile unsigned char*)patch_target = (unsigned char)(orig ^ 0xFF);

        dump_mask("[SDM] STAGE_PATCH (byte at 3/4 of .text)",
                  ad_sdm_check(&ctx, scratch, buf_size));

        *(volatile unsigned char*)patch_target = orig;
        unsigned long dummy = 0;
        VirtualProtect(patch_target, 16, old_prot, &dummy);
    }

    // STAGE_RESTORE
    dump_mask("[SDM] STAGE_RESTORE", ad_sdm_check(&ctx, scratch, buf_size));

    put("[SDM] === TEST END ===\n");
    return 0;
}
