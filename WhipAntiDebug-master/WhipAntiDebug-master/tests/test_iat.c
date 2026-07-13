// ===== file: tests/test_iat.c =====
//
// IAT target validation harness.
//   STAGE_CLEAN   — scan our own IAT, expect 0 hits
//   STAGE_HIJACK  — overwrite one IAT entry with a heap address, expect 1 hit
//   STAGE_RESTORE — restore, expect 0 hits
//
#include "antidebug/checks/integrity/iat_target.h"

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

static void dump_result(const char* tag, const ad_iat_result_t* r) {
    char line[160], num[16];
    put(tag);
    put("\n");

    u32_dec(num, r->iat_total);
    int i = 0, j;
    const char* p = "  IAT total scanned    : ";
    for (j = 0; p[j]; j++) line[i++] = p[j];
    for (j = 0; num[j]; j++) line[i++] = num[j];
    line[i++] = '\n'; line[i] = 0; put(line);

    u32_dec(num, r->hit_count);
    i = 0;
    const char* p2 = "  entries hijacked     : ";
    for (j = 0; p2[j]; j++) line[i++] = p2[j];
    for (j = 0; num[j]; j++) line[i++] = num[j];
    line[i++] = '\n'; line[i] = 0; put(line);

    u32 k;
    for (k = 0; k < r->hit_count; k++) {
        char hx[32];
        i = 0;
        const char* p3 = "    [!] slot ";
        for (j = 0; p3[j]; j++) line[i++] = p3[j];
        hex64(hx, (unsigned long long)(unsigned __int64)r->hits[k].iat_slot_addr);
        for (j = 0; j < 18; j++) line[i + j] = hx[j];
        i += 18;
        const char* p4 = "  target=";
        for (j = 0; p4[j]; j++) line[i++] = p4[j];
        hex64(hx, (unsigned long long)(unsigned __int64)r->hits[k].target_addr);
        for (j = 0; j < 18; j++) line[i + j] = hx[j];
        i += 18;
        line[i++] = '\n'; line[i] = 0;
        put(line);
    }
}

int main(void) {
    put("[IAT] === TEST START ===\n");

    // STAGE_CLEAN
    ad_iat_result_t r1;
    ad_iat_validate_self(&r1);
    dump_result("[IAT] STAGE_CLEAN", &r1);

    // STAGE_HIJACK: pick the first IAT slot we can write to and hijack it.
    // We need to find at least one IAT entry to experiment with.
    if (r1.iat_total == 0u) {
        put("[IAT] no IAT entries — cannot run hijack test\n");
        put("[IAT] === TEST END ===\n");
        return 0;
    }

    // Re-walk to locate the first IAT slot address (we don't store it in
    // result when clean, so re-scan manually using import tables).
    unsigned char* peb = (unsigned char*)__readgsqword(0x60);
    unsigned char* image = *(unsigned char**)(peb + 0x10);
    unsigned int pe_off = *(unsigned int*)(image + 0x3C);
    unsigned char* pe = image + pe_off;
    unsigned char* opt = pe + 24;
    unsigned int import_rva  = *(unsigned int*)(opt + 112 + 8);
    unsigned int iat_rva     = *(unsigned int*)(image + import_rva + 0x10);
    unsigned char* iat       = image + iat_rva;

    void** first_slot = (void**)(iat);
    void* orig_value = *first_slot;
    {
        char hx[32], line[96]; int i = 0, j;
        const char* p = "[IAT] first slot orig=";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        hex64(hx, (unsigned long long)(unsigned __int64)orig_value);
        for (j = 0; j < 18; j++) line[i + j] = hx[j];
        line[i + 18] = '\n'; line[i + 19] = 0; put(line);
    }

    unsigned long old_prot = 0;
    if (VirtualProtect(first_slot, 8, 0x04UL, &old_prot)) {  // PAGE_READWRITE
        // Replace with a heap address (simulating Detours-style hook).
        void* fake = VirtualAlloc((void*)0, 0x1000, 0x3000u, 0x40u);
        *first_slot = fake;

        ad_iat_result_t r2;
        ad_iat_validate_self(&r2);
        dump_result("[IAT] STAGE_HIJACK", &r2);

        // Restore
        *first_slot = orig_value;
        unsigned long dummy = 0;
        VirtualProtect(first_slot, 8, old_prot, &dummy);
    }

    ad_iat_result_t r3;
    ad_iat_validate_self(&r3);
    dump_result("[IAT] STAGE_RESTORE", &r3);

    put("[IAT] === TEST END ===\n");
    return 0;
}
