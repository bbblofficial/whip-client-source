// Test loader for WhipAD.dll — runs breakdown twice:
// 1) Before debugger attach (baseline)
// 2) After 30s wait (attach debugger during this window)
#include <stdio.h>
#pragma comment(lib, "kernel32.lib")

__declspec(dllimport) void*  __stdcall LoadLibraryA(const char*);
__declspec(dllimport) void*  __stdcall GetProcAddress(void*, const char*);
__declspec(dllimport) void   __stdcall Sleep(unsigned long);

typedef unsigned int (__cdecl *fn_score)(void);
typedef int          (__cdecl *fn_ready)(void);
typedef void         (__cdecl *fn_breakdown)(unsigned int*);

static void print_breakdown(const char* label, unsigned int* bd) {
    printf("\n=== %s ===\n", label);
    printf("  TOTAL SCORE   = %u\n", bd[0]);
    printf("  correlation=%u deep=%u cross=%u patch=%u exotic=%u advanced=%u extra=%u\n",
           bd[1], bd[2], bd[3], bd[4], bd[5], bd[6], bd[7]);

    // Key raw flags
    printf("  [flags] peb=%u ntgflag=%u heap=%u dbgport=%u dbgflags=%u hwbp=%u\n",
           bd[10], bd[11], bd[12], bd[13], bd[14], bd[15]);
    printf("  [flags] timing=%u syscall=%u ntclose=%u rdtsc=%u hooked=%u rwx=%u\n",
           bd[16], bd[17], bd[18], bd[19], bd[20], bd[21]);

    // Extra checks that fire
    printf("  [extra] tls=%u fakehwbp=%u attach=%u frida=%u xtimer=%u vad=%u\n",
           bd[22], bd[23], bd[24], bd[25], bd[26], bd[27]);
    printf("  [extra] unwind=%u veh=%u dbgui=%u handles=%u dlls=%u procscan=%u\n",
           bd[28], bd[29], bd[30], bd[31], bd[32], bd[33]);
    printf("  [extra] etw=%u trapSS=%u trapCTX=%u pgguard=%u\n",
           bd[34], bd[35], bd[36], bd[37]);

    // Advanced
    printf("  [adv] ghostCode=%u ghostNtdll=%u workset=%u excRip=%u xproc=%u\n",
           bd[38], bd[39], bd[40], bd[41], bd[42]);
    printf("  [adv] selfmod=%u sched=%u temporal=%u pipe=%u heisen=%u\n",
           bd[43], bd[44], bd[45], bd[46], bd[47]);
    printf("  [adv] excFP=%u imposs=%u pressure=%u scylla=%u\n",
           bd[48], bd[49], bd[50], bd[51]);

    // NEW CHECKS
    printf("  [NEW] remote_debug  = %u  %s\n", bd[52], bd[52] ? "DETECTED" : "clean");
    printf("  [NEW] anti_emulat   = %u  %s\n", bd[53], bd[53] ? "DETECTED" : "clean");
    printf("  [NEW] ept_split     = %u  %s\n", bd[54], bd[54] ? "DETECTED" : "clean");
    printf("  [NEW] heartbeat_stl = %u  %s\n", bd[55], bd[55] ? "STALLED" : "pumping");
    printf("  [NEW] wd_penalty    = %u\n", bd[56]);
    fflush(stdout);
}

int main(void) {
    printf("[*] Loading WhipAD.dll...\n"); fflush(stdout);
    void* dll = LoadLibraryA("C:\\Users\\Java\\CLionProjects\\WhipAntiDebugger\\tests\\WhipAD.dll");
    if (!dll) { printf("[-] FAILED\n"); return 1; }

    fn_ready IsReady = (fn_ready)GetProcAddress(dll, "ad_dll_is_ready");
    fn_breakdown GetBD = (fn_breakdown)GetProcAddress(dll, "ad_dll_get_breakdown");
    if (!IsReady || !GetBD) { printf("[-] Missing exports\n"); return 1; }

    printf("[*] Waiting for init...\n"); fflush(stdout);
    int wait = 0;
    while (!IsReady() && wait < 30) { Sleep(500); wait++; }
    if (!IsReady()) { printf("[-] Timeout\n"); return 1; }

    // RUN 1: Baseline (no debugger attached)
    unsigned int bd[64] = {0};
    GetBD(bd);
    print_breakdown("RUN 1 - BASELINE (no debugger attached)", bd);

    // Wait for debugger attach
    printf("\n[*] ATTACH DEBUGGER NOW — waiting 30 seconds...\n"); fflush(stdout);
    Sleep(30000);

    // RUN 2: After debugger attach
    unsigned int bd2[64] = {0};
    GetBD(bd2);
    print_breakdown("RUN 2 - AFTER DEBUGGER ATTACH", bd2);

    // Compare
    printf("\n=== DELTA (RUN2 - RUN1) ===\n");
    const char* names[] = {
        "score","corr","deep","cross","patch","exotic","adv","extra",
        "poison","raw","peb","ntgflag","heap","port","flags","hwbp",
        "timing","syscall","ntclose","rdtsc","hooked","rwx",
        "tls","fakehw","attach","frida","xtimer","vad","unwind","veh",
        "dbgui","handles","dlls","procscan","etw","trapSS","trapCTX","pgguard",
        "ghostC","ghostN","workset","excRip","xproc","selfmod","sched",
        "temporal","pipe","heisen","excFP","imposs","pressure","scylla",
        "remote","emulat","ept","heartbeat","wdpen"
    };
    int any_delta = 0;
    for (int i = 0; i < 57; i++) {
        if (bd2[i] != bd[i]) {
            int delta = (int)bd2[i] - (int)bd[i];
            printf("  %-12s: %u -> %u  (%+d)\n", names[i], bd[i], bd2[i], delta);
            any_delta = 1;
        }
    }
    if (!any_delta) printf("  (no changes)\n");

    printf("\n"); fflush(stdout);
    return 0;
}
