// ===== file: tests/test_ot.c =====
//
// Orphan thread detection harness.
// Scans our own threads, lists modules, classifies each thread's start
// address.
//
// Then spawns a thread whose start address is a MANUALLY-MAPPED RWX page
// (simulating CreateRemoteThread / injected DLL). Expected: orphan count
// increments by 1.
//
#include "antidebug/checks/threads/orphan_threads.h"

__declspec(dllimport) void  __stdcall OutputDebugStringA(const char*);
__declspec(dllimport) void  __stdcall Sleep(unsigned long);
__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int   __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) void* __stdcall VirtualAlloc(void*, u64, unsigned long, unsigned long);
__declspec(dllimport) void* __stdcall CreateThread(void*, u64, void*, void*, unsigned long, unsigned long*);

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

static void dump_scan(const char* tag, const ad_ot_result_t* r) {
    char line[160], num[16];
    put(tag);
    put("\n");

    u32_dec(num, r->module_count);
    int i = 0, j;
    const char* p1 = "  modules   : ";
    for (j = 0; p1[j]; j++) line[i++] = p1[j];
    for (j = 0; num[j]; j++) line[i++] = num[j];
    line[i++] = '\n'; line[i] = 0; put(line);

    u32_dec(num, r->thread_count);
    i = 0;
    const char* p2 = "  threads   : ";
    for (j = 0; p2[j]; j++) line[i++] = p2[j];
    for (j = 0; num[j]; j++) line[i++] = num[j];
    line[i++] = '\n'; line[i] = 0; put(line);

    u32_dec(num, r->orphan_count);
    i = 0;
    const char* p3 = "  orphans   : ";
    for (j = 0; p3[j]; j++) line[i++] = p3[j];
    for (j = 0; num[j]; j++) line[i++] = num[j];
    line[i++] = '\n'; line[i] = 0; put(line);

    // List each thread's verdict
    unsigned t;
    for (t = 0; t < r->thread_count; t++) {
        char hx[32];
        hex64(hx, (unsigned long long)(unsigned __int64)r->threads[t].start_addr);
        i = 0;
        const char* p4 = "   thread start=";
        for (j = 0; p4[j]; j++) line[i++] = p4[j];
        for (j = 0; j < 18; j++) line[i + j] = hx[j];
        i += 18;
        const char* v = r->threads[t].orphan ? "  [ORPHAN]\n" : "  [in module]\n";
        for (j = 0; v[j]; j++) line[i++] = v[j];
        line[i] = 0;
        put(line);
    }
}

// Simulated injected-thread entry point. Body placed in RWX private mem.
// It just sleeps and returns — we only care about its StartAddress.
static const unsigned char INJECTED_STUB[] = {
    0x48, 0x83, 0xEC, 0x28,             // sub rsp, 40
    0x48, 0xC7, 0xC1, 0xE8, 0x03, 0x00, 0x00,  // mov rcx, 1000
    0xFF, 0x15, 0x04, 0x00, 0x00, 0x00, // call qword ptr [rip+4] (points to Sleep ptr)
    0x48, 0x83, 0xC4, 0x28,             // add rsp, 40
    0x31, 0xC0,                         // xor eax, eax
    0xC3                                 // ret
};

int main(void) {
    put("[OT] === TEST START ===\n");

    // STAGE_BEFORE : scan before injection.
    ad_ot_result_t r1;
    ad_ot_scan(&r1);
    dump_scan("[OT] STAGE_BEFORE", &r1);

    // STAGE_INJECT : allocate an RWX page outside any loaded module,
    // drop a trivial stub there, spawn a thread on it.
    void* rwx = VirtualAlloc((void*)0, 0x1000, 0x3000UL, 0x40UL);
    if (!rwx) {
        put("[OT] VirtualAlloc failed\n");
        return 1;
    }
    // Infinite-loop stub so the thread is alive during the scan.
    //   EB FE    jmp $-2         (loops forever on itself)
    volatile unsigned char* code = (volatile unsigned char*)rwx;
    code[0] = 0xEB; code[1] = 0xFE;

    unsigned long tid = 0;
    void* th = CreateThread((void*)0, 0, (void*)rwx, (void*)0, 0, &tid);
    if (!th) {
        put("[OT] CreateThread failed\n");
        return 1;
    }
    {
        char hx[32], line[96]; int i = 0, j;
        const char* p = "[OT] injected thread start=";
        for (j = 0; p[j]; j++) line[i++] = p[j];
        hex64(hx, (unsigned long long)(unsigned __int64)rwx);
        for (j = 0; j < 18; j++) line[i + j] = hx[j];
        line[i + 18] = '\n'; line[i + 19] = 0;
        put(line);
    }

    // Wait briefly so the new thread is listed by NtQuerySystemInformation.
    Sleep(200);

    // STAGE_AFTER : scan again.
    ad_ot_result_t r2;
    ad_ot_scan(&r2);
    dump_scan("[OT] STAGE_AFTER", &r2);

    // Verdict
    if (r2.orphan_count > r1.orphan_count) {
        put("[OT] VERDICT: orphan count increased — injection visible\n");
    } else {
        put("[OT] VERDICT: orphan count unchanged — detection FAILED\n");
    }

    put("[OT] === TEST END ===\n");
    Sleep(500);
    return 0;
}
