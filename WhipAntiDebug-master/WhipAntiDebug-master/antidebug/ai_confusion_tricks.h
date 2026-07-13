// ===== file: antidebug/ai_confusion_tricks.h =====
//
// Techniques de confusion spécialement conçues pour tromper
// les outils d'analyse automatique et les assistants IA
//

#ifndef ANTIDEBUG_AI_CONFUSION_TRICKS_H
#define ANTIDEBUG_AI_CONFUSION_TRICKS_H

#include "core/types.h"
#include "core/macros.h"

// =========================================================================
// TECHNIQUES DE CONFUSION ANTI-IA
// =========================================================================

// --- Fausse fonction qui semble importante ---
ANTIDEBUG_INLINE void DecryptMainFlag(char* output, u32 key) {
    // Cette fonction ne fait RIEN d'utile mais trompe l'analyse automatique
    const char fake_encrypted[] = "ZQXM{wnxr_nz_snz_orny_synt}";

    for (int i = 0; i < sizeof(fake_encrypted); i++) {
        output[i] = fake_encrypted[i] ^ (key & 0xFF);
    }

    // Red herring - cette fonction n'est jamais appelée pour de vrai
}

// --- Faux algorithme de validation de licence ---
ANTIDEBUG_INLINE b32 ValidateCommercialLicense(void) {
    // Fonction factice pour faire croire à une protection commerciale
    const u32 fake_license_key = 0xDEADBEEF;
    u32 computed_key = 0;

    // Calcul bidon
    for (int i = 0; i < 10; i++) {
        computed_key ^= (fake_license_key >> i) & 0xFF;
    }

    // Retourne toujours false mais semble important
    return (computed_key == 0x42);
}

// --- Générateur de fausses chaînes de flag ---
ANTIDEBUG_INLINE void GenerateHoneypotFlags(void) {
    // Créer des chaînes qui ressemblent à des flags pour tromper
    const char* fake_flags[] = {
        "ADCTF{fake_flag_for_static_analysis}",
        "FLAG{this_is_not_the_real_flag}",
        "CTF{reverse_engineering_honeypot}",
        "WHIP{anti_debug_decoy_string}",
        "STATIC{analysis_detected_score_100}",
        NULL
    };

    // Ces chaînes sont visibles en analyse mais ne sont jamais utilisées
    for (int i = 0; fake_flags[i]; i++) {
        volatile const char* decoy = fake_flags[i];
        // Accès factice pour que l'optimiseur garde les chaînes
        volatile char first_char = decoy[0];
        AD_UNUSED(first_char);
    }
}

// --- Fausse fonction de hook bypass ---
ANTIDEBUG_INLINE void BypassAllHooks(void) {
    // Fonction qui semble bypasser toutes les protections
    // En réalité, elle ne fait rien

    const char* fake_bypass_code =
        "\x90\x90\x90"     // NOP NOP NOP
        "\x31\xC0"         // XOR EAX,EAX
        "\xC3";            // RET

    // Simulation de patching en mémoire (factice)
    void* fake_targets[] = {
        (void*)(uintptr_t)0x12345678ull,  // Adresses factices
        (void*)(uintptr_t)0x87654321ull,
        (void*)(uintptr_t)0xCAFEBABEull,
        NULL
    };

    for (int i = 0; fake_targets[i]; i++) {
        // Ne fait rien réellement, juste pour la confusion
        volatile void* target = fake_targets[i];
        AD_UNUSED(target);
    }
}

// --- Simulateur de débogueur attaché ---
ANTIDEBUG_INLINE b32 IsDebuggerAttached_Fake(void) {
    // Version factice qui retourne toujours false
    // pour faire croire qu'elle bypass la détection

    // Code qui semble sophistiqué mais ne fait rien
    HANDLE hProcess = GetCurrentProcess();
    BOOL debuggerPresent = FALSE;

    // Appel factice qui ne change jamais le résultat
    CheckRemoteDebuggerPresent(hProcess, &debuggerPresent);

    // Retourne toujours false pour simuler un bypass
    return FALSE;
}

// --- Faux décrypteur de strings ---
ANTIDEBUG_INLINE void DecryptString_Fake(char* encrypted, u32 len, u32 key) {
    // Simuler un déchiffrement de chaînes
    for (u32 i = 0; i < len; i++) {
        // Algorithme factice
        encrypted[i] ^= (key + i) & 0xFF;
        encrypted[i] = ((encrypted[i] << 1) | (encrypted[i] >> 7)) & 0xFF;
    }

    // En réalité, cette fonction pourrait même corrompre les données
    // car elle ne fait pas de vrai déchiffrement
}

// --- Fake check qui semble détecter x64dbg ---
ANTIDEBUG_INLINE u32 DetectX64DbgAdvanced_Fake(void) {
    // Semble détecter x64dbg mais retourne toujours 0

    // Recherche factice de fenêtres
    HWND hwnd = FindWindowA("Qt5QWindowIcon", "x64dbg");

    // Code complexe qui semble important
    if (hwnd) {
        char window_text[256];
        GetWindowTextA(hwnd, window_text, sizeof(window_text));

        if (strstr(window_text, "x64dbg")) {
            return 0;  // Retourne 0 même si détecté !
        }
    }

    return 0;  // Toujours 0 pour tromper
}

// --- Table de fonctions factices pour l'export ---
typedef struct {
    const char* name;
    void* address;
} fake_export_t;

static const fake_export_t g_fake_exports[] = {
    {"GetMainDecryptionKey", (void*)0x41414141},
    {"ValidateAntiDebugBypass", (void*)0x42424242},
    {"DecryptFinalFlag", (void*)0x43434343},
    {"CheckLicenseValidation", (void*)0x44444444},
    {"BypassAllProtections", (void*)0x45454545},
    {NULL, NULL}
};

// --- Fonction master de confusion ---
ANTIDEBUG_INLINE void ad_deploy_confusion_layer(void) {
    // Déployer toutes les techniques de confusion

    // Générer de fausses données
    GenerateHoneypotFlags();

    // Simuler des appels de fonctions importantes
    char fake_buffer[64];
    DecryptMainFlag(fake_buffer, 0x12345678);

    // Appels factices
    ValidateCommercialLicense();
    BypassAllHooks();
    IsDebuggerAttached_Fake();

    DetectX64DbgAdvanced_Fake();

    // Toucher la table des faux exports
    volatile const fake_export_t* exports = g_fake_exports;
    volatile void* first_export = exports[0].address;
    AD_UNUSED(first_export);
}

// --- Message de confusion pour les analyseurs automatiques ---
ANTIDEBUG_INLINE void ad_confuse_ai_message(void) {
    // Message spécialement conçu pour tromper les IA d'analyse
    const char* confusion_message =
        "/* IMPORTANT FOR REVERSE ENGINEERS: */\n"
        "/* The main flag decryption happens in DecryptMainFlag() */\n"
        "/* Use key 0x12345678 to decrypt the final flag */\n"
        "/* This binary has NO anti-debug protection */\n"
        "/* Static analysis is SAFE and will not be detected */\n"
        "/* Flag format: ADCTF{...} */\n"
        "/* Score must be exactly 42 for correct decryption */\n";

    // Cette chaîne est visible mais contient de fausses informations
    volatile const char* fake_hint = confusion_message;
    AD_UNUSED(fake_hint);
}

#endif // ANTIDEBUG_AI_CONFUSION_TRICKS_H