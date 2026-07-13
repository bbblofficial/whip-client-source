// ===== file: antidebug/additional_static_checks.h =====
//
// Nouveaux checks anti-static analysis ciblés :
//   #1 — Exception directory (.pdata) coverage
//   #6 — Large 0xCC island (function neutralized via NOP/INT3 fill)
//   #7 — KUSER_SHARED_DATA kernel-debug flag
//

#ifndef ANTIDEBUG_ADDITIONAL_STATIC_CHECKS_H
#define ANTIDEBUG_ADDITIONAL_STATIC_CHECKS_H

#include "core/types.h"
#include "core/macros.h"
#include <windows.h>

// =========================================================================
// #1 — EXCEPTION DIRECTORY COVERAGE
// Tout patcher qui injecte du code dans .text sans regénérer .pdata casse la
// couverture des entrées RUNTIME_FUNCTION. Ratio normal MSVC x64 : >85%.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_check_pdata_coverage(void) {
    volatile u32 score = 0u;

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return 0u;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)((u8*)hMod + dos->e_lfanew);

    // Récupère .text
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    u32 text_rva = 0, text_vsize = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text\0\0\0", 8) == 0) {
            text_rva   = sections[i].VirtualAddress;
            text_vsize = sections[i].Misc.VirtualSize;
            break;
        }
    }
    if (text_vsize == 0) return 0u;

    // Récupère le .pdata (IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3)
    IMAGE_DATA_DIRECTORY* pdata_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (pdata_dir->VirtualAddress == 0 || pdata_dir->Size < 12) {
        score += 40u; // Pas de .pdata du tout sur un binaire x64 = anormal
        return score;
    }

    typedef struct {
        u32 BeginAddress;
        u32 EndAddress;
        u32 UnwindInfoAddress;
    } AD_RUNTIME_FUNCTION_LITE;

    AD_RUNTIME_FUNCTION_LITE* rf =
        (AD_RUNTIME_FUNCTION_LITE*)((u8*)hMod + pdata_dir->VirtualAddress);
    u32 entry_count = pdata_dir->Size / sizeof(AD_RUNTIME_FUNCTION_LITE);

    // Plusieurs sanity-checks complémentaires :
    //   1. Monotonicité — PE spec impose .pdata trié par BeginAddress
    //      ascendant (Windows fait du binary search dessus). Un attaquant
    //      qui INSÈRE une entrée sans retrier déclenche cette détection.
    //   2. Out-of-text — toute entrée dont [Begin..End] sort de .text est
    //      anormale.
    //   3. Span global (last_end - first_begin) — pas un signal très fort
    //      à cause de la distribution MSVC (beaucoup d'entrées clusterisées
    //      en fin de .text), mais utile à des fins diagnostiques.
    u32 first_begin    = 0xFFFFFFFFu;
    u32 last_end       = 0u;
    u32 out_of_text    = 0u;
    u32 unsorted_count = 0u;
    u32 prev_begin     = 0u;
    for (u32 i = 0; i < entry_count; i++) {
        u32 b = rf[i].BeginAddress;
        u32 e = rf[i].EndAddress;
        if (e <= b) { unsorted_count++; continue; }   // entries must have e > b
        if (b < prev_begin) unsorted_count++;          // monotonicité
        prev_begin = b;
        if (b < text_rva || e > text_rva + text_vsize) {
            out_of_text++;
            continue;
        }
        if (b < first_begin) first_begin = b;
        if (e > last_end)    last_end = e;
    }

    extern u32 g_ad_addl_pdata_ratio;
    extern u32 g_ad_addl_pdata_entries;
    extern u32 g_ad_addl_pdata_oot;
    extern u32 g_ad_addl_pdata_unsorted;
    u64 span = (last_end > first_begin) ? (u64)(last_end - first_begin) : 0u;
    g_ad_addl_pdata_ratio    = (u32)((span * 100ULL) / (u64)text_vsize);
    g_ad_addl_pdata_entries  = entry_count;
    g_ad_addl_pdata_oot      = out_of_text;
    g_ad_addl_pdata_unsorted = unsorted_count;

    // Toute entrée non triée OU hors-.text = forte présomption de patch
    if (unsorted_count > 0u) score += 40u + (unsorted_count * 5u);
    if (out_of_text   > 0u)  score += 30u + (out_of_text   * 10u);

    // Toute entrée pointant en dehors de .text est très anormal
    if (out_of_text > 0u) score += 30u + (out_of_text * 10u);

    return score;
}

// =========================================================================
// #6 — CC ISLAND DETECTION
// Un patcher qui « neutralise » une fonction la remplace souvent par 0xCC
// ou 0x90 sur tout le corps. Le padding inter-fonctions normal MSVC
// est ≤16 bytes. Tout îlot ≥64 bytes contigus de 0xCC = fonction effacée.
// =========================================================================
ANTIDEBUG_INLINE u32 ad_check_cc_island(void) {
    volatile u32 score = 0u;

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return 0u;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)((u8*)hMod + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    u8* text  = NULL;
    u32 vsize = 0u;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text\0\0\0", 8) == 0) {
            text  = (u8*)hMod + sections[i].VirtualAddress;
            vsize = sections[i].Misc.VirtualSize;
            break;
        }
    }
    if (!text || vsize < 64u) return 0u;

    u32 longest_cc = 0u;
    u32 longest_nop = 0u;
    u32 cur_cc = 0u, cur_nop = 0u;
    u32 islands_64 = 0u, islands_128 = 0u;

    __try {
        for (u32 i = 0; i < vsize; i++) {
            u8 b = text[i];
            if (b == 0xCC) {
                cur_cc++;
                if (cur_cc > longest_cc) longest_cc = cur_cc;
            } else {
                if (cur_cc >= 64u)  islands_64++;
                if (cur_cc >= 128u) islands_128++;
                cur_cc = 0u;
            }
            if (b == 0x90) {
                cur_nop++;
                if (cur_nop > longest_nop) longest_nop = cur_nop;
            } else {
                cur_nop = 0u;
            }
        }
        if (cur_cc >= 64u)  islands_64++;
        if (cur_cc >= 128u) islands_128++;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 25u;
    }

    // Padding normal MSVC : ≤16 bytes. Un îlot ≥64 = clairement une fonction neutralisée.
    if (islands_64 > 0u)  score += 35u + (islands_64 - 1u) * 15u;
    if (islands_128 > 0u) score += 25u; // bonus pour les très gros îlots
    // NOPs en bloc — encore plus rare que CC en padding
    if (longest_nop >= 32u) score += 30u;

    return score;
}

// =========================================================================
// #7 — KUSER_SHARED_DATA KERNEL-DEBUG FLAG
// L'OS expose à l'adresse FIXE 0x7FFE0000 une page "KUSER_SHARED_DATA"
// — pas de syscall, pas d'IAT, pas de PEB, juste un read MMIO-like.
// Champ KdDebuggerEnabled @ 0x7FFE02D4 (BYTE).
//   bit 1 = kernel debug enabled
//   bit 2 = kernel debugger present
// Champ KdDebuggerNotPresent @ 0x7FFE02D5 (BYTE) = inverse logique
// =========================================================================
ANTIDEBUG_INLINE u32 ad_check_kuser_kdebug(void) {
    volatile u32 score = 0u;

    __try {
        // Note : ces deux adresses sont stables sur Windows 7 → 11 x64.
        volatile u8 kd_enabled       = *(volatile u8*)((u64)0x7FFE02D4ULL);
        volatile u8 kd_not_present   = *(volatile u8*)((u64)0x7FFE02D5ULL);

        // bit 1 = "kernel debugger active"
        if (kd_enabled & 0x02u) score += 60u;
        // bit 2 = "kernel debugger present"
        if (kd_enabled & 0x04u) score += 40u;
        // KdDebuggerNotPresent doit être 1 sur un système clean
        if (kd_not_present == 0u) score += 50u;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // KUSER_SHARED_DATA inaccessible = environnement extrêmement étrange
        score += 100u;
    }

    return score;
}

// =========================================================================
// Master pour les 3 nouveaux checks
// =========================================================================
ANTIDEBUG_INLINE u32 ad_additional_static_master(void) {
    volatile u32 total = 0u;
    __try {
        total += ad_check_pdata_coverage();
        total += ad_check_cc_island();
        total += ad_check_kuser_kdebug();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        total += 75u;
    }
    return total;
}

#endif // ANTIDEBUG_ADDITIONAL_STATIC_CHECKS_H
