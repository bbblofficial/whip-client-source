#pragma once

#include <cstdint>
#include <string>

// Sentinel — wrapper anti-debug du Loader.
//
// Stratégie anti-NOP :
//
//   1. `init()` est appelé une fois au démarrage. Il initialise le state
//      anti-debug et lance un premier `ad_run_hardened` pour stocker un
//      score chiffré dans un value_guard interne.
//
//   2. `taint(byte* data, u32 len)` mélange le score chiffré dans n'importe
//      quel buffer (HWID, sessionToken, requête file, etc.). Si un debugger
//      est détecté, le buffer est corrompu → le serveur rejette la requête.
//      Aucun `if (debuggerPresent)` à NOPer : l'attaque doit forger le bon
//      score, ce qui demande de savoir TOUTES les checks qui ont fired.
//
//   3. `recheck()` relance les hardened checks avec un PRNG seedé sur RDTSC,
//      mettant à jour le score interne. Appelé à chaque step du Loader pour
//      qu'un NOP d'un seul appel ne suffise pas.
//
//   4. `verify()` checke l'intégrité du dispatcher lui-même via
//      `ad_verify_result()` (le framework détecte si quelqu'un a patché
//      `ad_run_hardened` pour retourner zero).
//
//   5. Tout est appelable inline depuis n'importe quel TU. Le helper interne
//      stocke son state dans des globales chiffrées (mem_encrypt vault).
namespace Sentinel {

    // À appeler une fois au démarrage du Loader (avant tout I/O réseau).
    // Init le state anti-debug, lance un premier check, scelle le canary.
    void init();

    // À appeler une fois avant exit. Désinstalle les 4 VEH décoy +
    // stoppe les noise threads spawnés par ad::StackProtect. Critique
    // pour le path manual-mapped (sinon VEH et threads pointent vers
    // du code unmappé une fois que la mapper restore le PEB) et anodin
    // pour le path standalone (kernel reclaim de toute façon).
    void cleanup();

// Taint un buffer arbitraire avec le score chiffré actuel.
    // Si le score est non-nul, le buffer est XOR'd avec une keystream dérivée.
    // Si score = 0 (clean), le buffer est inchangé.
    void taint(uint8_t* data, uint32_t length);

    // Phase 1+2 auth_tag — élimine le bypass NOPable de taint().
    //
    // Phase 1 : HMAC(salt, buf || score)[:8]. Phase 2 mixe un algoSeed
    // per-download dans la clé : keyMaterial = SHA-256(salt || algoSeed),
    // tag = HMAC-SHA256(keyMaterial, buf || score_le32)[:8]. Reverse
    // d'un loader ne donne pas l'algo d'un autre (crack non-portable).
    //
    // Avec [[nodiscard]], un patcher qui RET-Ok la fonction laisse le tag
    // à 0 → le serveur reject. Bypass = forger le tag = connaître salt +
    // algoSeed + score → impossible sans la DB serveur.
    [[nodiscard]] uint64_t deriveAuthTag(const uint8_t* buf, uint32_t length,
                                         const uint8_t salt[16],
                                         const uint8_t algoSeed[32],
                                         const uint8_t codeFingerprint[32]);

    // Relance ad_run_hardened et met à jour le score interne.
    // Pas de valeur de retour exposée publiquement (pas de cible NOPable).
    void recheck();

    // Verify l'intégrité du dispatcher. À combiner avec recheck() régulier.
    // Si patch détecté, vault le score à 0xFFFFFFFF (donc taint corrompt tout).
    void verify();

    // Mémoire raw du score actuel (encrypted). Exposé pour latent_tamper checks.
    uint64_t snapshot();

    // Externally-reported threat. Folds bits into the score consumed by
    // deriveAuthTag. Used by AntiRpmGuard to corrupt future auth_tags
    // when an external process is caught reading our memory — server
    // observes the mismatch and triggers Phase 4 ban via
    // ViolationType.AUTH_TAG_MISMATCH (weight 50, 2 strikes = ban).
    // Bits OR-accumulate; never decrease. See DUMP_THREAT_MODEL.md §5.5.
    void reportExternalThreat(uint32_t bits);

    // Fresh one-shot scan for RE/analysis tools (Wireshark, IDA, x64dbg…).
    // Does NOT use the cached score — always runs a live detection pass.
    // Returns true if any tool is found; false if the machine is clean.
    bool reDetect();

    // Numeric tool mask from the last reDetect() call (th32 hit_mask bits).
    // 0x001=x64dbg 0x002=CE 0x004=Fiddler 0x008=IDA 0x010=Wireshark
    // 0x020=Cutter 0x040=Olly 0x080=WinDbg 0x200=Charles
    uint32_t reDetectMask();

    // Decrypted score from the last recheck() cycle.
    // >= 50 means at least one check fired (debugger, hardware BP, timing, etc.).
    uint32_t score();

    // Check counters from the last recheck() cycle.
    uint32_t checksRun();
    uint32_t checksHit();

    // Bitmask of individual checks that fired in the last recheck() cycle.
    // Bit layout mirrors ReverseDetectedHandler.FLAG_* on the server so that
    // describeFlags() renders human-readable names in the log and webhook.
    //   bit  0=PEB.BeingDebugged  bit  1=NtGlobalFlag   bit  2=HeapFlags
    //   bit  3=DebugPort          bit  4=DebugFlags      bit  5=HWBP
    //   bit  6=RDTSC_TIMING       bit  7=SYSCALL_TIMING  bit  8=NtClose
    //   bit  9=RDTSC_DOUBLE       bit 10=NTDLL_HOOKED    bit 11=PAGE_RWX
    //   bit 31=DISPATCHER_PATCHED
    uint32_t hitFlags();

    // Layer-by-layer breakdown of the last recheck() cycle as a compact
    // key=value string (e.g. "corr=0 deep=12 patch=8 exotic=18 adv=7 ...").
    // Sent verbatim in the REVERSE_DETECTED report field so the server can
    // log exactly which layer pushed the score over the threshold.
    std::string layerReport();
}
