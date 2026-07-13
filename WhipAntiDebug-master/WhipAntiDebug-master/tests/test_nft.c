// ===== file: tests/test_nft.c =====
//
// ntdll full .text integrity harness.
//   STAGE_INIT    — locate ntdll.text, hash 64 chunks
//   STAGE_CLEAN   — expect mask=0
//   STAGE_PATCH   — flip one byte in a known ntdll function, expect bit set
//   STAGE_RESTORE — expect mask=0
//
#include "antidebug/checks/integrity/ntdll_full_text.h"
#include "antidebug/core/api_hash.h"

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

static void dump_mask64(const char* tag, unsigned long long mask) {
    char hx[32], line[96];
    hex64(hx, mask);
    int i = 0, j;
    for (j = 0; tag[j]; j++) line[i++] = tag[j];
    line[i++] = ' '; line[i++] = 'm'; line[i++] = 'a'; line[i++] = 's'; line[i++] = 'k'; line[i++] = '=';
    for (j = 0; j < 18; j++) line[i + j] = hx[j];
    line[i + 18] = '\n'; line[i + 19] = 0;
    put(line);

    // List chunk indexes that fired
    for (j = 0; j < 64; j++) {
        if (mask & (1ULL << j)) {
            char out[32], num[8];
            u32_dec(num, (unsigned)j);
            const char* p = "    [!] chunk ";
            int ii = 0, k;
            for (k = 0; p[k]; k++) out[ii++] = p[k];
            for (k = 0; num[k]; k++) out[ii++] = num[k];
            out[ii++] = ' '; out[ii++] = 'c'; out[ii++] = 'h'; out[ii++] = 'a';
            out[ii++] = 'n'; out[ii++] = 'g'; out[ii++] = 'e'; out[ii++] = 'd';
            out[ii++] = '\n'; out[ii] = 0;
            put(out);
        }
    }
}

int main(void) {
    ad_nft_ctx_t ctx;
    int k;
    for (k = 0; k < (int)sizeof(ctx); k++)
        ((volatile unsigned char*)&ctx)[k] = 0;

    put("[NFT] === TEST START ===\n");

    if (!ad_nft_init(&ctx)) {
        put("[NFT] STAGE_INIT failed\n");
        return 1;
    }

    {
        char hx[32], line[96], num[16];
        int i = 0, j;
        const char* p = "[NFT] STAGE_INIT ok  .text @";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        hex64(hx, (unsigned long long)(unsigned __int64)ctx.text_base);
        for (j = 0; j < 18; j++) line[i + j] = hx[j];
        i += 18;
        const char* p2 = "  size=";
        for (j = 0; p2[j]; j++) line[i++] = p2[j];
        u32_dec(num, ctx.text_size);
        for (j = 0; num[j]; j++) line[i++] = num[j];
        const char* p3 = " bytes, chunks=";
        for (j = 0; p3[j]; j++) line[i++] = p3[j];
        u32_dec(num, AD_NFT_CHUNK_COUNT);
        for (j = 0; num[j]; j++) line[i++] = num[j];
        const char* p4 = ", chunk_size=";
        for (j = 0; p4[j]; j++) line[i++] = p4[j];
        u32_dec(num, ctx.chunk_size);
        for (j = 0; num[j]; j++) line[i++] = num[j];
        line[i++] = '\n'; line[i] = 0;
        put(line);
    }

    // STAGE_CLEAN
    dump_mask64("[NFT] STAGE_CLEAN", ad_nft_check(&ctx));

    // STAGE_PATCH: patch the first byte of NtGetContextThread (resolvable).
    void* target = ad_resolve_api(AD_HASH_NTDLL, AD_HASH("NtGetContextThread"));
    if (target) {
        unsigned long old_prot = 0;
        if (VirtualProtect(target, 16, 0x40UL, &old_prot)) {
            unsigned char orig = *(volatile unsigned char*)target;
            *(volatile unsigned char*)target = 0xE9;

            dump_mask64("[NFT] STAGE_PATCH (NtGetContextThread first byte)",
                        ad_nft_check(&ctx));

            *(volatile unsigned char*)target = orig;
            unsigned long dummy = 0;
            VirtualProtect(target, 16, old_prot, &dummy);
        }
    } else {
        put("[NFT] could not resolve NtGetContextThread — skipping patch test\n");
    }

    dump_mask64("[NFT] STAGE_RESTORE", ad_nft_check(&ctx));

    put("[NFT] === TEST END ===\n");
    return 0;
}
