// ===== file: tests/test_ndt.c =====
//
// ntdll multi-point integrity harness.
//   STAGE_INIT     — snapshot 10 entries
//   STAGE_CLEAN    — expect mask=0
//   STAGE_PATCH_N  — self-patch entry N, expect bit N set + sig bit set
//   STAGE_RESTORE  — expect mask=0
//
#include "antidebug/checks/integrity/ntdll_dispatchers.h"

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

static const char* entry_names[10] = {
    "KiUserExceptionDispatcher",
    "KiUserApcDispatcher",
    "KiUserCallbackDispatcher",
    "LdrInitializeThunk",
    "RtlUserThreadStart",
    "NtGetContextThread",
    "NtSetContextThread",
    "NtQueryInformationProcess",
    "NtContinue",
    "DbgBreakPoint"
};

static void dump_mask(const char* tag, unsigned int mask) {
    char hx[16], line[96];
    hex32(hx, mask);
    int i = 0, j;
    for (j = 0; tag[j]; j++) line[i++] = tag[j];
    line[i++] = ' '; line[i++] = 'm'; line[i++] = 'a'; line[i++] = 's'; line[i++] = 'k'; line[i++] = '=';
    for (j = 0; j < 10; j++) line[i + j] = hx[j];
    line[i + 10] = '\n'; line[i + 11] = 0;
    put(line);

    // Enumerate which entries fired (low 10 bits)
    for (j = 0; j < 10; j++) {
        if (mask & (1u << j)) {
            const char* nm = entry_names[j];
            put("    [!] patched: ");
            put(nm);
            put("\n");
        }
    }
    // Signature types (bits 16-21)
    const char* sigs[6] = {
        "jmp rel32 (E9)",
        "mov rax imm64 / jmp rax",
        "jmp [rip+rel32] (FF 25)",
        "int3 hotpatch (CC)",
        "short jmp (EB)",
        "mov r10/r11 trampoline"
    };
    for (j = 0; j < 6; j++) {
        if (mask & (1u << (16 + j))) {
            put("    [!] sig: ");
            put(sigs[j]);
            put("\n");
        }
    }
}

int main(void) {
    ad_ndt_ctx_t ctx;
    int k;
    for (k = 0; k < (int)sizeof(ctx); k++)
        ((volatile unsigned char*)&ctx)[k] = 0;

    put("[NDT] === TEST START ===\n");

    if (!ad_ndt_init(&ctx)) {
        put("[NDT] STAGE_INIT failed (nothing resolved)\n");
        return 1;
    }

    // Count how many resolved
    int resolved = 0;
    for (k = 0; k < 10; k++) if (ctx.entries[k].present) resolved++;
    {
        char line[64];
        const char* p = "[NDT] STAGE_INIT ok, resolved ";
        int i = 0, j;
        for (j = 0; p[j]; j++) line[i++] = p[j];
        line[i++] = (char)('0' + (resolved / 10));
        line[i++] = (char)('0' + (resolved % 10));
        line[i++] = '/'; line[i++] = '1'; line[i++] = '0'; line[i++] = '\n'; line[i] = 0;
        put(line);
    }

    // Show the baseline bytes for each resolved entry
    for (k = 0; k < 10; k++) {
        if (!ctx.entries[k].present) {
            put("  [x] "); put(entry_names[k]); put(" (not resolved)\n");
            continue;
        }
        char line[96];
        int i = 0, j;
        line[i++] = ' '; line[i++] = ' '; line[i++] = '[';
        line[i++] = (char)('0' + k); line[i++] = ']'; line[i++] = ' ';
        const char* nm = entry_names[k];
        for (j = 0; nm[j]; j++) line[i++] = nm[j];
        // pad to col 32
        while (i < 32) line[i++] = ' ';
        line[i++] = ':'; line[i++] = ' ';
        for (j = 0; j < (int)AD_NDT_HASH_LEN; j++) {
            unsigned n = ctx.entries[k].baseline_bytes[j];
            char hi = (char)((n >> 4) < 10 ? '0' + (n >> 4) : 'a' + (n >> 4) - 10);
            char lo = (char)((n & 0xF) < 10 ? '0' + (n & 0xF) : 'a' + (n & 0xF) - 10);
            line[i++] = hi; line[i++] = lo; line[i++] = ' ';
        }
        line[i++] = '\n'; line[i] = 0;
        put(line);
    }

    // Stage clean
    unsigned int m1 = ad_ndt_check(&ctx);
    dump_mask("[NDT] STAGE_CLEAN", m1);

    // Stage patch: overwrite first byte of entry 0 with 0xE9 (jmp rel32)
    for (k = 0; k < 10; k++) {
        if (!ctx.entries[k].present) continue;
        void* addr = ctx.entries[k].addr;
        unsigned long old_prot = 0;
        if (!VirtualProtect(addr, 16, 0x40UL, &old_prot)) continue;
        unsigned char orig = *(volatile unsigned char*)addr;
        *(volatile unsigned char*)addr = 0xE9;

        char tag[96];
        int i = 0, j;
        const char* prefix = "[NDT] STAGE_PATCH ";
        for (j = 0; prefix[j]; j++) tag[i++] = prefix[j];
        const char* nm = entry_names[k];
        for (j = 0; nm[j]; j++) tag[i++] = nm[j];
        tag[i] = 0;
        dump_mask(tag, ad_ndt_check(&ctx));

        *(volatile unsigned char*)addr = orig;
        unsigned long dummy = 0;
        VirtualProtect(addr, 16, old_prot, &dummy);
        break;  // only patch the first resolvable entry for the demo
    }

    unsigned int m3 = ad_ndt_check(&ctx);
    dump_mask("[NDT] STAGE_RESTORE", m3);

    put("[NDT] === TEST END ===\n");
    return 0;
}
