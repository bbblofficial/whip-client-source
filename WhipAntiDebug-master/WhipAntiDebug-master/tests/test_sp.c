// ===== file: tests/test_sp.c =====
//
// Section-protection drift harness.
//   STAGE_INIT   — snapshot sections + expected protections
//   STAGE_CLEAN  — verify nothing drifted
//   STAGE_DRIFT  — VirtualProtect .text to PAGE_EXECUTE_READWRITE
//   STAGE_RESTORE — put it back
//
#include "antidebug/checks/integrity/section_protection.h"

__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int   __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) void  __stdcall OutputDebugStringA(const char*);
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

static const char* prot_name(unsigned int p) {
    switch (p) {
        case AD_PAGE_NOACCESS:          return "NOACCESS";
        case AD_PAGE_READONLY:          return "R";
        case AD_PAGE_READWRITE:         return "RW";
        case AD_PAGE_WRITECOPY:         return "WC";
        case AD_PAGE_EXECUTE:           return "X";
        case AD_PAGE_EXECUTE_READ:      return "RX";
        case AD_PAGE_EXECUTE_READWRITE: return "RWX";
        case AD_PAGE_EXECUTE_WRITECOPY: return "WXC";
        default:                        return "?";
    }
}

static void dump_sections(const ad_sp_ctx_t* c) {
    put("[SP] sections:\n");
    unsigned int i, j;
    for (i = 0; i < c->count; i++) {
        char line[128];
        int li = 0;
        line[li++] = ' '; line[li++] = ' ';
        line[li++] = '['; line[li++] = (char)('0' + (i / 10)); line[li++] = (char)('0' + (i % 10)); line[li++] = ']';
        line[li++] = ' ';
        for (j = 0; j < 8 && c->sections[i].name[j]; j++) line[li++] = (char)c->sections[i].name[j];
        while (li < 18) line[li++] = ' ';
        line[li++] = 'e'; line[li++] = 'x'; line[li++] = 'p'; line[li++] = '=';
        const char* p = prot_name(c->sections[i].expected_prot);
        for (j = 0; p[j]; j++) line[li++] = p[j];
        while (li < 30) line[li++] = ' ';
        line[li++] = 'a'; line[li++] = 'c'; line[li++] = 't'; line[li++] = '=';
        unsigned int act = ad_sp_query_prot(c->sections[i].base);
        p = prot_name(act);
        for (j = 0; p[j]; j++) line[li++] = p[j];
        line[li++] = '\n'; line[li] = 0;
        put(line);
    }
}

static void dump_result(const char* tag, const ad_sp_ctx_t* c, const ad_sp_result_t* r) {
    put(tag);
    put("\n");
    if (r->hit_count == 0) {
        put("  no drift\n");
        return;
    }
    unsigned i, j;
    for (i = 0; i < r->hit_count; i++) {
        const ad_sp_hit_t* h = &r->hits[i];
        const ad_sp_section_t* s = &c->sections[h->section_index];
        char line[128];
        int li = 0;
        const char* pref = "    [!] section ";
        for (j = 0; pref[j]; j++) line[li++] = pref[j];
        for (j = 0; j < 8 && s->name[j]; j++) line[li++] = (char)s->name[j];
        while (li < 24) line[li++] = ' ';
        line[li++] = 'e'; line[li++] = 'x'; line[li++] = 'p'; line[li++] = '=';
        const char* p = prot_name(h->expected_prot);
        for (j = 0; p[j]; j++) line[li++] = p[j];
        while (li < 36) line[li++] = ' ';
        line[li++] = 'a'; line[li++] = 'c'; line[li++] = 't'; line[li++] = '=';
        p = prot_name(h->actual_prot);
        for (j = 0; p[j]; j++) line[li++] = p[j];
        line[li++] = '\n'; line[li] = 0;
        put(line);
    }
}

int main(void) {
    ad_sp_ctx_t ctx;
    int k; for (k = 0; k < (int)sizeof(ctx); k++)
        ((volatile unsigned char*)&ctx)[k] = 0;

    put("[SP] === TEST START ===\n");
    if (!ad_sp_init(&ctx)) { put("[SP] STAGE_INIT failed\n"); return 1; }
    put("[SP] STAGE_INIT ok\n");
    dump_sections(&ctx);

    ad_sp_result_t r1;
    ad_sp_check(&ctx, &r1);
    dump_result("[SP] STAGE_CLEAN", &ctx, &r1);

    // Find .text index
    int text_idx = -1;
    for (k = 0; k < (int)ctx.count; k++) {
        if (ctx.sections[k].name[0]=='.' && ctx.sections[k].name[1]=='t' &&
            ctx.sections[k].name[2]=='e' && ctx.sections[k].name[3]=='x' &&
            ctx.sections[k].name[4]=='t') { text_idx = k; break; }
    }
    if (text_idx < 0) { put("[SP] .text not found\n"); return 1; }

    // Force .text to RWX
    unsigned long old_prot = 0;
    VirtualProtect(ctx.sections[text_idx].base, 4096,
                   0x40UL /* PAGE_EXECUTE_READWRITE */, &old_prot);
    ad_sp_result_t r2;
    ad_sp_check(&ctx, &r2);
    dump_result("[SP] STAGE_DRIFT", &ctx, &r2);

    // Restore
    unsigned long dummy = 0;
    VirtualProtect(ctx.sections[text_idx].base, 4096, old_prot, &dummy);

    ad_sp_result_t r3;
    ad_sp_check(&ctx, &r3);
    dump_result("[SP] STAGE_RESTORE", &ctx, &r3);

    put("[SP] === TEST END ===\n");
    return 0;
}
