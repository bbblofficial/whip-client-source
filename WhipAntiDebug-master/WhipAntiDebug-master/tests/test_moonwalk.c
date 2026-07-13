// ===== file: test_moonwalk.c =====
//
// Tests du stack moonwalk — trois niveaux :
//
//   1. PROGRAMMATIQUE : capture les adresses de retour dans la probe,
//      vérifie qu'elles tombent dans ntdll après le spoof.
//
//   2. VISUEL (OutputDebugStringA) : affiche "REAL: 0x..." vs "SPOOFED: 0x..."
//      dans DebugView ou l'output panel de x64dbg.
//
//   3. DEBUGGER : instructions pour vérifier dans x64dbg / WinDbg.
//
// Compilation :
//   #pragma optimize("y", off)  ← frame pointers requis pour le stack walk
//   /Oy-                        ← ou ce flag dans les options du projet
//
// Ajouter à CMakeLists.txt :
//   add_executable(MoonwalkTest test_moonwalk.c)
//   target_link_libraries(MoonwalkTest PRIVATE WhipAntiDebugger)
//   target_compile_options(MoonwalkTest PRIVATE /Oy-)  ← frame pointers
//

// Frame pointers obligatoires pour le stack walk manuel
#pragma optimize("y", off)

#include "antidebug/core/syscall_bridge.h"
#include "antidebug/stack/moonwalk.h"
#include "antidebug/stack/moonwalk_asm.h"

// OutputDebugStringA pour output sans printf/CRT
// (seul import WinAPI toléré dans un test)
__declspec(dllimport) void __stdcall OutputDebugStringA(const char* lpOutputString);

// ---------------------------------------------------------------------------
// Utilitaires sans CRT
// ---------------------------------------------------------------------------

// Conversion u64 → hex string dans buf (au moins 19 chars : "0x" + 16 + '\0')
static void u64_to_hex(u64 val, char* buf) {
    const char hex[] = "0123456789ABCDEF";
    buf[0] = '0'; buf[1] = 'x';
    int i;
    for (i = 0; i < 16; i++) {
        buf[2 + i] = hex[(val >> (60 - i * 4)) & 0xF];
    }
    buf[18] = '\0';
}

// Concaténation minimale dans un buffer statique
static void dbg_print(const char* prefix, u64 addr) {
    static char buf[64];
    // copy prefix
    int i = 0;
    while (prefix[i] && i < 40) { buf[i] = prefix[i]; i++; }
    // hex addr
    char hex[19];
    u64_to_hex(addr, hex);
    int j = 0;
    while (hex[j] && (i + j) < 62) { buf[i + j] = hex[j]; j++; }
    buf[i + j]     = '\n';
    buf[i + j + 1] = '\0';
    OutputDebugStringA(buf);
}

// ---------------------------------------------------------------------------
// Infos ntdll : base + taille (pour vérifier si une adresse est dans ntdll)
// ---------------------------------------------------------------------------
static void* g_ntdll_base = (void*)0;
static u32   g_ntdll_size = 0;

static void init_ntdll_info(void) {
#if defined(_MSC_VER)
    u8* peb    = (u8*)__readgsqword(0x60);
    u8* ldr    = *(u8**)(peb  + 0x18);
    u8* first  = *(u8**)(ldr  + 0x10);   // InLoadOrderModuleList.Flink → EXE
    u8* second = *(u8**)first;             // → ntdll entry
    g_ntdll_base = *(void**)(second + 0x30);  // DllBase
    g_ntdll_size = *(u32* )(second + 0x40);   // SizeOfImage
#endif
}

static b32 addr_in_ntdll(void* addr) {
    u64 a   = (u64)addr;
    u64 lo  = (u64)g_ntdll_base;
    u64 hi  = lo + (u64)g_ntdll_size;
    return (b32)(a >= lo && a < hi);
}

// ---------------------------------------------------------------------------
// Capture des adresses de retour sur la stack
//
// Utilise la chaîne RBP (frame pointer chain).
// Requiert /Oy- (frame pointers non omis).
//
// Pour chaque frame :
//   [RBP + 0x00] = RBP du frame parent (saved frame pointer)
//   [RBP + 0x08] = adresse de retour de ce frame
// ---------------------------------------------------------------------------
#define MAX_CAPTURED 8

typedef struct {
    void* addrs[MAX_CAPTURED];
    u32   count;
} stack_capture_t;

// Capture N adresses de retour depuis le frame courant.
// DOIT être __declspec(noinline) pour avoir son propre frame.
__declspec(noinline)
static stack_capture_t capture_stack(u32 depth) {
    stack_capture_t cap;
    u32 i;
    for (i = 0; i < MAX_CAPTURED; i++) cap.addrs[i] = (void*)0;
    cap.count = 0;

    if (depth > MAX_CAPTURED) depth = MAX_CAPTURED;

#if defined(_MSC_VER)
    // RBP du frame courant = adresse du slot ret - 8
    // _AddressOfReturnAddress() pointe sur [RSP] = notre adresse de retour
    u8* fp = (u8*)_AddressOfReturnAddress() - sizeof(void*);

    for (i = 0; i < depth; i++) {
        void* ret = *(void**)(fp + 8);  // [RBP+8] = return address
        cap.addrs[i] = ret;
        cap.count++;

        u8* parent = *(u8**)fp;         // [RBP+0] = saved RBP
        if (!parent || parent <= fp) break;
        fp = parent;
    }
#endif
    return cap;
}

// ---------------------------------------------------------------------------
// Probe 1 : appelée NORMALEMENT (pas de spoof)
// Capture la stack et affiche les adresses
// ---------------------------------------------------------------------------
__declspec(noinline)
static b32 probe_normal(void) {
    stack_capture_t cap = capture_stack(4);
    b32 any_ntdll = 0;
    u32 i;

    OutputDebugStringA("[MOONWALK TEST] --- Normal call ---\n");
    for (i = 0; i < cap.count; i++) {
        b32 in_ntdll = addr_in_ntdll(cap.addrs[i]);
        dbg_print(in_ntdll ? "  [ntdll]  ret=" : "  [OWN]   ret=", (u64)cap.addrs[i]);
        if (in_ntdll) any_ntdll = 1;
    }
    // Sans spoof : aucune adresse ne devrait être dans ntdll (sauf si on est
    // déjà appelé depuis ntdll, ce qui n'est pas le cas ici)
    return any_ntdll;
}

// ---------------------------------------------------------------------------
// Probe 2 : appelée via MoonwalkCall (stack spoofée)
// Capture la stack et affiche les adresses
// ---------------------------------------------------------------------------
typedef struct { b32 result; } probe_spoofed_args_t;

__declspec(noinline)
static void probe_spoofed_fn(void* raw) {
    probe_spoofed_args_t* out = (probe_spoofed_args_t*)raw;

    stack_capture_t cap = capture_stack(4);
    b32 any_ntdll = 0;
    u32 i;

    OutputDebugStringA("[MOONWALK TEST] --- Spoofed call (MoonwalkCall) ---\n");
    for (i = 0; i < cap.count; i++) {
        b32 in_ntdll = addr_in_ntdll(cap.addrs[i]);
        dbg_print(in_ntdll ? "  [ntdll]  ret=" : "  [OWN]   ret=", (u64)cap.addrs[i]);
        if (in_ntdll) any_ntdll = 1;
    }

    out->result = any_ntdll;  // 1 = spoof réussi (au moins 1 frame pointe ntdll)
}

// ---------------------------------------------------------------------------
// Test de l'API C inline (ad_moonwalk_begin/end)
// ---------------------------------------------------------------------------
__declspec(noinline)
static b32 probe_singleframe(const ad_decoy_table_t* tbl) {
    ad_moonwalk_ctx_t mw;
    ad_moonwalk_begin(&mw, tbl->addrs[0]);

    // Lire l'adresse de retour actuelle APRÈS le spoof
    void* cur_ret = *(void**)_AddressOfReturnAddress();
    b32 spoofed = addr_in_ntdll(cur_ret);

    dbg_print("[MOONWALK TEST] single-frame ret after spoof=", (u64)cur_ret);
    dbg_print("                in ntdll: ", (u64)spoofed);

    ad_moonwalk_end(&mw);
    return spoofed;
}

// ---------------------------------------------------------------------------
// Point d'arrêt interactif pour x64dbg / WinDbg
//
// Mettre un BP ICI, puis regarder la call stack dans l'UI du debugger.
// Sans moonwalk : on voit main() → test_run() → probe_*()
// Avec moonwalk : on voit ntdll!xxx → ntdll!xxx → probe_*()
// ---------------------------------------------------------------------------
__declspec(noinline)
static void bp_target_normal(void) {
    // x64dbg : bp sur cet adresse, puis regarder Call Stack panel
    // WinDbg : bp /1 <addr> "k; g"
    __debugbreak();  // retirer en production
}

__declspec(noinline)
static void bp_target_spoofed(void* arg) {
    (void)arg;
    // Même chose, mais appelé via MoonwalkCall.
    // La call stack affichée par x64dbg devrait montrer ntdll.
    __debugbreak();
}

// ---------------------------------------------------------------------------
// Runner principal
// ---------------------------------------------------------------------------
__declspec(noinline)
static void test_run(const ad_decoy_table_t* tbl) {
    OutputDebugStringA("[MOONWALK TEST] ========== START ==========\n");

    // ── Test 1 : appel normal (baseline) ────────────────────────────────────
    b32 normal_has_ntdll = probe_normal();
    if (!normal_has_ntdll) {
        OutputDebugStringA("[MOONWALK TEST] PASS : appel normal ne montre pas ntdll\n");
    } else {
        OutputDebugStringA("[MOONWALK TEST] WARN : ntdll detecte dans appel normal (inattendu)\n");
    }

    // ── Test 2 : MoonwalkCall (ASM trampoline, multi-frame) ─────────────────
    probe_spoofed_args_t spoofed_out;
    spoofed_out.result = 0;
    MoonwalkCall(probe_spoofed_fn, (void**)tbl->addrs, 4u, &spoofed_out);

    if (spoofed_out.result) {
        OutputDebugStringA("[MOONWALK TEST] PASS : MoonwalkCall — ntdll visible dans stack\n");
    } else {
        OutputDebugStringA("[MOONWALK TEST] FAIL : MoonwalkCall — ntdll PAS visible (frame pointers?)\n");
    }

    // ── Test 3 : ad_moonwalk_begin/end (single-frame, pur C) ────────────────
    b32 single_ok = probe_singleframe(tbl);
    if (single_ok) {
        OutputDebugStringA("[MOONWALK TEST] PASS : single-frame spoof OK\n");
    } else {
        OutputDebugStringA("[MOONWALK TEST] FAIL : single-frame spoof — ret addr non spoofee\n");
    }

    // ── Test 4 : BP targets pour debugger interactif ────────────────────────
    // Sans spoof : call stack réelle
    bp_target_normal();

    // Avec spoof : call stack spoofée (regarder dans x64dbg ici)
    MoonwalkCall(bp_target_spoofed, (void**)tbl->addrs, 4u, (void*)0);

    OutputDebugStringA("[MOONWALK TEST] ========== END ==========\n");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int main(void) {
    whip_bridge_init();
    init_ntdll_info();

    dbg_print("[MOONWALK TEST] ntdll base = ", (u64)g_ntdll_base);
    dbg_print("[MOONWALK TEST] ntdll size = ", (u64)g_ntdll_size);

    // Construire la table de leurres
    ad_decoy_table_t tbl;
    ad_decoy_table_init(&tbl);

    u32 i;
    for (i = 0; i < tbl.count; i++) {
        dbg_print("[MOONWALK TEST] decoy[i] = ", (u64)tbl.addrs[i]);
    }

    test_run(&tbl);
    return 0;
}
