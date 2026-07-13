// ===== file: test_new_checks.c =====
//
// Test isolé pour les nouveaux checks :
//   - al-khaser : parent_process, se_debug, write_watch, vm_vendor
//   - anti-ScyllaHide : 6 checks comportementaux
//
// Utilisation :
//   Exécuter directement         → tous les checks doivent retourner 0
//   Ouvrir dans x64dbg           → parent_process + les checks debug doivent firer
//   Activer ScyllaHide dans x64dbg → les 6 checks ScyllaHide doivent firer
//   Exécuter dans une VM         → vm_vendor_known doit firer
//
// Output : OutputDebugStringA (visible dans DebugView ou x64dbg output panel)
//

#include "antidebug/core/syscall_bridge.h"
#include "antidebug/checks/debug/parent_process.h"
#include "antidebug/checks/debug/se_debug.h"
#include "antidebug/checks/runtime/write_watch.h"
#include "antidebug/checks/vm/vm_detect.h"
#include "antidebug/checks/advanced/anti_scyllahide.h"
#include "antidebug/checks/debug/dbgui_patch.h"
#include "antidebug/checks/debug/handle_scan.h"
#include "antidebug/checks/debug/suspicious_dlls.h"
#include "antidebug/checks/debug/process_scan.h"
#include "antidebug/checks/runtime/etw_detect.h"
#include "antidebug/checks/exceptions/trap_flag.h"
#include "antidebug/checks/debug/handle_trace.h"
#include "antidebug/checks/debug/system_info.h"
#include "antidebug/checks/runtime/guard_pages.h"
#include "antidebug/checks/debug/debug_object_remove.h"
#include "antidebug/core/mem_encrypt.h"
#include "antidebug/checks/timing/qpc_timing.h"
#include "antidebug/checks/runtime/hook_detect.h"
#include "antidebug/checks/runtime/instrumentation.h"
#include "antidebug/checks/runtime/thread_monitor.h"
#include "antidebug/checks/advanced/ghost_breakpoints.h"
#include "antidebug/checks/advanced/pipeline_desync.h"
#include "antidebug/checks/advanced/scheduler_sync.h"
#include "antidebug/checks/advanced/exception_fingerprint.h"
#include "antidebug/checks/advanced/impossible_states.h"
#include "antidebug/checks/advanced/selfmod_race.h"
#include "antidebug/checks/advanced/pressure_test.h"
#include "antidebug/checks/advanced/temporal_traps.h"
#include "antidebug/checks/advanced/cross_process.h"
#include "antidebug/checks/advanced/heisenberg.h"
#include "antidebug/checks/debug/peb.h"
#include "antidebug/checks/debug/debug_port.h"
#include "antidebug/checks/debug/flags.h"
#include "antidebug/checks/breakpoints/int3_scan.h"
#include "antidebug/checks/breakpoints/hardware.h"
#include "antidebug/checks/exceptions/seh.h"
#include "antidebug/checks/threads/hide_thread.h"
#include "antidebug/checks/timing/rdtsc.h"
#include "antidebug/checks/timing/loops.h"
#include "antidebug/checks/integrity/code_hash.h"
#include "antidebug/checks/integrity/anti_patch.h"

#ifdef _MSC_VER
#include <intrin.h>
#endif

__declspec(dllimport) void   __stdcall OutputDebugStringA(const char* lpOutputString);
__declspec(dllimport) void*  __stdcall GetStdHandle(unsigned long nStdHandle);
__declspec(dllimport) int    __stdcall WriteFile(void* hFile, const void* lpBuffer,
                                                  unsigned long nNumberOfBytesToWrite,
                                                  unsigned long* lpNumberOfBytesWritten,
                                                  void* lpOverlapped);
__declspec(dllimport) void*  __stdcall CreateFileA(const char* lpFileName,
                                                    unsigned long dwDesiredAccess,
                                                    unsigned long dwShareMode,
                                                    void* lpSecurityAttributes,
                                                    unsigned long dwCreationDisposition,
                                                    unsigned long dwFlagsAndAttributes,
                                                    void* hTemplateFile);

// ---------------------------------------------------------------------------
// Utilitaires sans CRT
// ---------------------------------------------------------------------------
static void str_append(char* dst, int* pos, const char* src) {
    while (*src && *pos < 126) { dst[(*pos)++] = *src++; }
}

static void print_stdout(const char* s) {
    int len = 0;
    const char* p = s;
    while (*p++) len++;
    if (len <= 0) return;

    unsigned long written = 0;

    // Stdout
    static void* hOut = (void*)0;
    if (!hOut) hOut = GetStdHandle((unsigned long)(-11));  // STD_OUTPUT_HANDLE
    if (hOut && hOut != (void*)(unsigned long long)(-1))
        WriteFile(hOut, s, (unsigned long)len, &written, (void*)0);

    // Log file C:\temp\test_result.txt  (CREATE_ALWAYS=2, GENERIC_WRITE=0x40000000, FILE_ATTRIBUTE_NORMAL=0x80)
    static void* hLog = (void*)0;
    if (!hLog) {
        hLog = CreateFileA("C:\\temp\\test_result.txt",
                           0x40000000UL,  // GENERIC_WRITE
                           0UL,           // no share
                           (void*)0,
                           2UL,           // CREATE_ALWAYS
                           0x80UL,        // FILE_ATTRIBUTE_NORMAL
                           (void*)0);
        if (hLog == (void*)(unsigned long long)(-1)) hLog = (void*)0;
    }
    if (hLog)
        WriteFile(hLog, s, (unsigned long)len, &written, (void*)0);
}

static void u32_to_dec(u32 val, char* buf) {
    char tmp[12];
    int n = 0;
    if (val == 0) { buf[0] = '0'; buf[1] = '\0'; return; }
    while (val > 0) { tmp[n++] = '0' + (char)(val % 10); val /= 10; }
    int i;
    for (i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    buf[n] = '\0';
}

// Imprime :  "[PASS] name\n"  ou  "[FAIL] name  score=N\n"
static void print_result(const char* name, u32 score) {
    char buf[128];
    int pos = 0;
    char num[12];

    if (score == 0) {
        str_append(buf, &pos, "[PASS] ");
        str_append(buf, &pos, name);
    } else {
        str_append(buf, &pos, "[FAIL] ");
        str_append(buf, &pos, name);
        str_append(buf, &pos, "  score=");
        u32_to_dec(score, num);
        str_append(buf, &pos, num);
    }
    buf[pos++] = '\n';
    buf[pos]   = '\0';
    OutputDebugStringA(buf);
    print_stdout(buf);
}

static void print_section(const char* title) {
    char buf[128];
    int pos = 0;
    str_append(buf, &pos, "\n--- ");
    str_append(buf, &pos, title);
    str_append(buf, &pos, " ---\n");
    buf[pos] = '\0';
    OutputDebugStringA(buf);
    print_stdout(buf);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int main(void) {
    // Capture TSC before anything else — used by timing_consistency check
#ifdef _MSC_VER
    u64 init_tsc = __rdtsc();
#else
    u64 init_tsc = 0;
#endif

    OutputDebugStringA("=== test_new_checks : debut ===\n");
    print_stdout("=== test_new_checks : debut ===\n");

    if (!whip_bridge_init()) {
        OutputDebugStringA("[FATAL] whip_bridge_init() a echoue\n");
        print_stdout("[FATAL] whip_bridge_init() a echoue\n");
        return 1;
    }

    // ── Init stateful checks ─────────────────────────────────────────────────
    // Memory encryption key (RDTSC-derived, unique per-run)
    ad_memkey_t mk;
    ad_memkey_init(&mk);

    // Temporal trap: snapshot environment at T0, verify later at T+N
    ad_temporal_ctx_t temporal;
    ad_temporal_trap_plant(&temporal, &mk);

    // Heisenberg state: evolving encrypted value
    ad_heisenberg_ctx_t heisenberg;
    ad_heisenberg_init(&heisenberg, &mk);

    // Code hash baseline — capture before any check that might patch code
    u64 code_hash_baseline = ad_code_hash_capture((const void*)main, 256u);

    // Self-hash table — CRC32 baseline for functions we want to monitor
    ad_self_hash_table_t hash_tbl;
    {
        const void* monitored[] = { (const void*)main, (const void*)print_result };
        ad_self_hash_init(&hash_tbl, monitored, 2u);
    }

    // ── al-khaser checks ─────────────────────────────────────────────────────
    print_section("al-khaser checks");

    // Parent process : retourne 1 si le processus parent est un debugger connu
    // (x64dbg, WinDbg, IDA, Cheat Engine, etc.)
    // Attendu : 0 si lancé normalement, 1 si lancé depuis x64dbg
    print_result("parent_is_debugger",  (u32)ad_parent_is_debugger());

    // SeDebugPrivilege : détecte si notre token a SE_DEBUG activé
    // Attendu : 0 dans un process normal, 1 si lancé par un outil élevé
    print_result("se_debug_privilege",  (u32)ad_se_debug_privilege());

    // WriteWatch : détecte l'instrumentation DBI/sandbox via MEM_WRITE_WATCH
    // Attendu : 0 sur bare metal, 1 sous DynamoRIO / PIN / sandbox
    print_result("write_watch_check",   (u32)ad_write_watch_check());

    // VM vendor : CPUID 0x40000000 → string connue (VMware / VBox / KVM…)
    // Attendu : 0 sur bare metal, 1 en VM
    print_result("vm_vendor_known",     (u32)ad_vm_vendor_known());

    // ── PEB / classic debug checks ────────────────────────────────────────────
    print_section("PEB / classic checks");

    // PEB.BeingDebugged (offset +0x02) — le plus basique
    // Attendu : 0 sans debugger, 1 si x64dbg attaché (ScyllaHide patch ça)
    print_result("peb_being_debugged",   (u32)ad_peb_being_debugged());

    // NtGlobalFlag (PEB+0xBC) — heap flags spéciaux sous debugger
    // Attendu : 0 normal, 1 si flags 0x70 présents (FLG_HEAP_ENABLE_TAIL_CHECK etc.)
    print_result("peb_nt_global_flag",   (u32)ad_peb_nt_global_flag());

    // Heap.Flags / Heap.ForceFlags — valeurs anormales sous debugger
    // Attendu : 0 normal, 1 si heap a été créé avec debug flags
    print_result("heap_flags",           (u32)ad_heap_flags());

    // NtQueryInformationProcess(ProcessDebugPort=7) — port debug non-nul
    // Attendu : 0 sans debugger, 1 si x64dbg (ScyllaHide patch ce syscall)
    print_result("debug_port",           (u32)ad_debug_port());

    // NtQueryInformationProcess(ProcessDebugFlags=31) — inverse : 0 = debuggé
    // Attendu : 0 (flag présent = pas debuggé) normal, 1 si debugger
    print_result("debug_flags",          (u32)ad_debug_flags());

    // NtQueryInformationProcess(ProcessDebugObjectHandle=30) — handle non-nul
    // Attendu : 0 normal, 1 si x64dbg (ScyllaHide hook raté → direct syscall)
    print_result("debug_object_handle",  (u32)ad_debug_object_handle());

    // Heuristique processus parent suspect (nom inhabituel)
    // Attendu : 0 si lancé normalement, heuristique approximative
    print_result("suspicious_parent",    (u32)ad_suspicious_parent());

    // ── ScyllaHide checks ─────────────────────────────────────────────────────
    print_section("anti-ScyllaHide checks");

    // 1. NtYieldExecution retourne STATUS_ACCESS_DENIED quand ScyllaHide est actif
    // Attendu : 0 sans ScyllaHide, 1 avec
    print_result("sh_yield_denied",      (u32)ad_sh_yield_denied());

    // 2. GetTickCount figé : ScyllaHide avance le compteur de +1 par appel
    //    alors que KUSER_SHARED_DATA reflète le vrai temps
    // Attendu : 0 sans ScyllaHide, 1 avec
    print_result("sh_tickcount_frozen",  (u32)ad_sh_tickcount_frozen());

    // 3. NtQuerySystemTime figé : même principe, delta fixe de 10000 par appel
    // Attendu : 0 sans ScyllaHide, 1 avec
    print_result("sh_systime_frozen",    (u32)ad_sh_systime_frozen());

    // 4. Dr0 effacé dans le contexte d'exception par KiUserExceptionDispatcher
    //    ScyllaHide patch ce hook pour zeroed Dr0-Dr7 dans chaque exception
    // Attendu : 0 sans ScyllaHide, 1 avec
    print_result("sh_dr_exc_clear",      (u32)ad_sh_dr_exception_clear());

    // 5. Compte les stubs ntdll patchés avec FF25 (JMP indirect 14 bytes)
    //    ScyllaHide hook ~20 stubs ; >=2 détectés = positif
    // Attendu : 0 sans ScyllaHide, 1 avec
    print_result("sh_stub_hook_count",   (u32)ad_sh_stub_hook_count());

    // 6. PPID via NtQueryInformationProcess (syscall direct) vs
    //    NtQuerySystemInformation via hook ScyllaHide → mismatch si spooféd
    // Attendu : 0 sans ScyllaHide, 1 avec
    print_result("sh_ppid_mismatch",     (u32)ad_sh_ppid_mismatch());

    // ── Score composite ScyllaHide ────────────────────────────────────────────
    {
        u32 total = ad_scyllahide_master();
        char buf[64];
        int pos = 0;
        char num[12];
        str_append(buf, &pos, "\n[*] score ScyllaHide composite = ");
        u32_to_dec(total, num);
        str_append(buf, &pos, num);
        str_append(buf, &pos, "  (seuil detection >= 9)\n");
        buf[pos] = '\0';
        OutputDebugStringA(buf);
        print_stdout(buf);
    }

    // ── Extra checks ─────────────────────────────────────────────────────
    print_section("extra checks");

    // DbgUiRemoteBreakin / DbgBreakPoint / NtCreateDebugObject hook detection
    // Attendu : PASS sans debugger, FAIL si un outil a patché ces stubs
    print_result("dbgui_patch_check",    (u32)ad_dbgui_patch_check());

    // Handle scan : processus externes avec handles debug sur notre PID
    // Attendu : PASS sans debugger, FAIL si x64dbg / CE est attaché
    print_result("handle_scan",          (u32)ad_handle_scan());

    // DLLs suspectes chargées dans notre processus (ScyllaHide, x64bridge…)
    // Attendu : PASS sans debugger, FAIL si plugin injecté
    print_result("suspicious_dlls",      (u32)ad_suspicious_dlls_check());

    // Scan de tous les processus actifs : x64dbg, WinDbg, IDA, CE…
    // Attendu : PASS si aucun debugger ouvert, FAIL sinon
    print_result("process_scan",         (u32)ad_process_scan());

    // ETW hook : EtwEventWrite / EtwEventWriteFull patchés
    // Attendu : PASS sans outil d'instrumentation, FAIL si Frida / API Monitor…
    print_result("etw_hook_detect",      (u32)ad_etw_hook_detect());

    // Trap Flag : EXCEPTION_SINGLE_STEP intercepté avant notre handler
    // Attendu : PASS (handler fire normalement)
    print_result("trap_flag_singlestep", (u32)ad_trap_flag_single_step());

    // Trap Flag context leak : TF encore set dans CONTEXT lors de l'exception
    // Attendu : PASS (kernel clear TF normalement)
    print_result("trap_flag_ctx_leak",   (u32)ad_trap_flag_context_leak());

    // ── Checks avancés ───────────────────────────────────────────────────────
    print_section("advanced checks");

    // CloseHandle trap : NtClose(handle_invalide) lève 0xC0000008 si debugger présent
    // Direct syscall → pas de NtClose dans la call stack, difficile à hooker
    // Attendu : PASS sans debugger, FAIL sous x64dbg (même avec ScyllaHide si sans NtClose protect)
    print_result("close_handle_trap",    (u32)ad_close_handle_trap());

    // Kernel debugger : SystemKernelDebuggerInformation (class 35)
    // Détecte WinDbg en mode kernel / HyperDbg
    // Attendu : PASS sur système normal, FAIL si kd actif
    print_result("kernel_debugger",      (u32)ad_kernel_debugger());

    // Guard page trap : PAGE_GUARD violation swallowed par le debugger
    // Teste la politique d'exception du debugger pour une classe différente
    // Attendu : PASS (exception arrive à notre handler), FAIL si debugger l'avale
    print_result("guard_page_trap",      (u32)ad_guard_page_trap());

    // NtRemoveProcessDebug : détache ACTIVEMENT le debugger
    // Retourne 1 si un debugger était présent et a été détaché
    // ATTENTION : crashe x64dbg — mettre en DERNIER dans sa propre section
    print_result("remove_debug_object",  (u32)ad_remove_debug_object());

    // ── Runtime hook / instrumentation ───────────────────────────────────────
    print_section("runtime: hooks & instrumentation");

    // Vérifie les stubs ntdll : cherche E9/FF25/CC/NOP au lieu de 4C 8B D1 B8
    // Attendu : PASS sans outil, FAIL si Frida / API Monitor / DbgUI hooké
    print_result("ntdll_hooks",           (u32)ad_detect_ntdll_hooks());

    // QPC timing : boucle LCG calibrée + NtQueryPerformanceCounter direct
    // Attendu : PASS sur bare metal, FAIL si instrumentation DBI ralentit
    print_result("qpc_timing",            (u32)ad_qpc_timing());

    // PEB LDR scan : détecte modules suspects (frida, dynamorio, dbghelp…)
    // Attendu : PASS sans DBI injecté, FAIL si Frida/Pin chargé
    print_result("suspicious_modules",    (u32)ad_detect_suspicious_modules());

    // ProcessInstrumentationCallback (class 40) non-NULL = quelqu'un nous instrumente
    // Attendu : PASS normal, FAIL si Frida intercepte les syscall returns
    print_result("instr_callback",        (u32)ad_instrumentation_callback_check());

    // ── Thread monitor ────────────────────────────────────────────────────────
    print_section("thread monitor");

    // DR0 canary : écrit une valeur magique, relit — le debugger l'écrase
    // Attendu : PASS sans HW BP actifs, FAIL si debugger utilise DR0
    print_result("dr_canary",             (u32)ad_dr_canary());

    // Single processor heuristic : sandbox/VM souvent = 1 core
    // Attendu : PASS (>=2 cores), FAIL en sandbox 1-core
    print_result("single_processor",      (u32)ad_single_processor_check());

    // TSC consistency : > 300 milliards de cycles depuis init = suspendu
    // Attendu : PASS (run normal <100s), FAIL si long step-through
    print_result("timing_consistency",    (u32)ad_timing_consistency(init_tsc));

    // ── Advanced: execution anomalies ────────────────────────────────────────
    print_section("advanced: execution");

    // Pipeline desync : variance TSC autour de CPUID — single-step la modifie
    // Attendu : PASS normal, FAIL en single-step mode
    print_result("pipeline_desync",       (u32)ad_pipeline_desync_check());

    // Scheduler sync : thread worker libre vs main single-steppé → sauts compteur
    // Attendu : PASS normal, FAIL si main thread est single-steppé
    print_result("scheduler_sync",        (u32)ad_scheduler_sync_check());

    // Self-modifying race : page RWX modifiée depuis thread pendant exécution
    // Attendu : PASS (timing normal), FAIL si sérialisation debugger détectée
    print_result("selfmod_race",          (u32)ad_selfmod_race_check());

    // Exception pressure : 200 exceptions DIV/0 ; mesure cycles/exception
    // Attendu : PASS (<15000 cycles/exc), FAIL sous debugger (round-trip lent)
    print_result("pressure_test",         (u32)ad_pressure_test_check());

    // ── Advanced: exception fingerprinting ──────────────────────────────────
    print_section("advanced: exception fp");

    // Fingerprint 4 types d'exceptions — pattern ≠ 0xF = debugger modifie le flux
    // Attendu : PASS (0xF = tous handlers ont tiré), FAIL sous debugger
    print_result("exception_fp",          (u32)ad_exception_fingerprint_check());

    // États impossibles : TF, INT2D, DIV0, rapid exceptions — comportements bugués
    // Attendu : PASS (handlers ok), FAIL si debugger consomme les exceptions
    print_result("impossible_states",     (u32)ad_impossible_states_check());

    // ── Advanced: memory / ghost BP ──────────────────────────────────────────
    print_section("advanced: memory");

    // Ghost breakpoint : compare lecture directe vs NtReadVirtualMemory (kernel)
    // Divergence = CoW → debugger a posé un 0xCC software BP
    // Attendu : PASS sans BP sur main(), FAIL si BP posé dans la région scannée
    print_result("ghost_bp_main",         (u32)ad_ghost_breakpoint_check((const void*)main, 256u));

    // Ghost BP sur ntdll : scan de la zone .text ntdll
    // Attendu : PASS propre, FAIL si BP ntdll (ex. NtCreateFile patché)
    print_result("ghost_bp_ntdll",        (u32)ad_ghost_breakpoint_ntdll());

    // Cross-process validation : kernel debug port vs PEB.BeingDebugged
    // Mismatch = ScyllaHide/outil a patché le PEB mais pas le kernel
    // Attendu : PASS (cohérent), FAIL si spoofing PEB
    {
        ad_cross_proc_ctx_t cross;
        print_result("cross_process",     (u32)ad_cross_process_validate(&cross));
    }

    // ── Timing checks ────────────────────────────────────────────────────────
    print_section("timing checks");

    // RDTSC step : CPUID-sérialisé ; delta anormalement grand = single-step
    // Attendu : PASS normal, FAIL si step-through ou hyperviseur intercepte RDTSC
    print_result("rdtsc_timing",         (u32)ad_rdtsc_timing());

    // RDTSC double lfence : deux lectures consécutives ; delta trop grand = interception
    // Attendu : PASS normal, FAIL sous debugger lent
    print_result("rdtsc_double",         (u32)ad_rdtsc_double());

    // Loop timing LCG : calibre une boucle et mesure ; ralentissement = debugger
    // Attendu : PASS normal, FAIL sous step-through
    print_result("loop_timing",          (u32)ad_loop_timing());

    // ── Breakpoint detection ──────────────────────────────────────────────────
    print_section("breakpoint detection");

    // Scan d'INT3 (0xCC) dans les 20 premiers bytes de main()
    // Attendu : PASS normal, FAIL si BP logiciel posé sur main()
    print_result("int3_scan_main",       (u32)ad_int3_scan((const void*)main));

    // Scan depuis le call site retour : cherche 0xCC dans la pile d'appel
    // Attendu : PASS normal, FAIL si BP posé juste avant notre return
    print_result("caller_int3_scan",     (u32)ad_caller_int3_scan());

    // Hardware breakpoints : NtGetContextThread, vérifie DR0-DR3/DR7
    // Attendu : PASS sans HW BP, FAIL si x64dbg a posé des HW BP sur nous
    print_result("hardware_bps",         (u32)ad_hardware_breakpoints());

    // ── SEH exception checks ──────────────────────────────────────────────────
    print_section("SEH exceptions");

    // INT3 via __debugbreak() : exception capturée normalement → handler fire
    // Attendu : PASS (notre handler tire), FAIL si debugger avale l'exception
    print_result("seh_breakpoint",       (u32)ad_seh_breakpoint());

    // Divide-by-zero SEH : EXCEPTION_INT_DIVIDE_BY_ZERO doit arriver à notre handler
    // Attendu : PASS, FAIL si le debugger absorbe l'exception
    print_result("seh_div_zero",         (u32)ad_seh_divide_by_zero());

    // Access violation SEH : lecture NULL doit atteindre notre handler
    // Attendu : PASS, FAIL si le debugger la swallow
    print_result("seh_access_violation", (u32)ad_seh_access_violation());

    // Fastfail probe : teste le comportement de __fastfail sous le debugger
    // Attendu : PASS normal, FAIL si comportement altéré
    print_result("seh_fastfail_probe",   (u32)ad_seh_fastfail_probe());

    // ── Integrity checks ─────────────────────────────────────────────────────
    print_section("integrity checks");

    // Page protection : .text doit être PAGE_EXECUTE_READ, pas PAGE_EXECUTE_READWRITE
    // Attendu : PASS (RX), FAIL si patché en RWX pour nous modifier
    print_result("page_protection",      (u32)ad_check_page_protection((const void*)main));

    // Prologue check : main() doit commencer par les bytes attendus (pas JMP/NOP/CC)
    // Attendu : PASS propre, FAIL si inline hook ou BP injecté
    print_result("prologue_check",       (u32)ad_check_prologue((const void*)main));

    // INT3 count : nombre de 0xCC dans les 256 premiers bytes de main()
    // Attendu : 0 PASS, N FAIL si software BP présent
    print_result("int3_count",           (u32)(ad_count_int3((const void*)main, 256u) > 0u));

    // Code hash (FNV-1a) : compare hash actuel vs baseline capturé à T0
    // Attendu : PASS (identique), FAIL si bytes modifiés depuis le début
    print_result("code_hash",            (u32)ad_code_hash_check((const void*)main, 256u, code_hash_baseline));

    // Self-hash CRC32 (SSE4.2) : vérifie main() + print_result() vs baseline
    // Attendu : PASS (identique), FAIL si l'une des fonctions a été hookée
    print_result("self_hash_crc32",      (u32)(ad_self_hash_check(&hash_tbl) > 0u));

    // ── Thread defense ────────────────────────────────────────────────────────
    print_section("thread defense");

    // NtSetInformationThread(ThreadHideFromDebugger) — masque le thread au debugger
    // ad_hide_thread() returns 1 on success (thread hidden) → score 0 = PASS
    //                          0 on failure (couldn't hide)  → score 1 = FAIL
    // ATTENTION sous x64dbg SANS ScyllaHide : peut tuer le processus immédiatement
    // Avec ScyllaHide : retourne succès sans cacher réellement (verify_hidden_bypass détecte ça)
    print_result("hide_thread",          (u32)(!ad_hide_thread()));

    // Vérifie que le hide est RÉEL : NtQueryInformationThread relit le flag
    // Attendu : 0 (thread caché, PASS) sans ScyllaHide
    //           1 (bypass détecté, FAIL) si ScyllaHide a intercepté le Set
    print_result("verify_hidden_bypass", (u32)ad_verify_thread_hidden());

    // ── Advanced: temporal / heisenberg ──────────────────────────────────────
    print_section("advanced: temporal");

    // Temporal trap : compare PEB.BeingDebugged / NtGlobalFlag / TSC maintenant
    // vs snapshot chiffré pris à T0 (avant les checks)
    // Attendu : PASS (aucun changement), FAIL si debugger attaché entre T0 et ici
    print_result("temporal_trap",         (u32)ad_temporal_trap_verify(&temporal, &mk));

    // Heisenberg : valeur chiffrée qui évolue à chaque lecture
    // Si un memory scanner a lu le storage entre init et ici → mismatch
    // Attendu : PASS (seul lecteur), FAIL si scanner externe a lu la valeur
    print_result("heisenberg",            (u32)ad_heisenberg_check(&heisenberg, &mk));

    OutputDebugStringA("=== test_new_checks : fin ===\n");
    print_stdout("=== test_new_checks : fin ===\n");
    return 0;
}