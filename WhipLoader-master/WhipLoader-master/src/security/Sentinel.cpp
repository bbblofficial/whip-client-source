#pragma optimize("", off)
#include "security/Sentinel.h"

#include <Windows.h>
#include <atomic>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#define VMP_BEGIN_ULTRA(x) VMProtectBeginUltra(x)
#define VMP_END()          VMProtectEnd()
#else
#define VMP_BEGIN_ULTRA(x) ((void)0)
#define VMP_END()          ((void)0)
#endif

// Implémentation réelle dans Sentinel_bridge.c (le framework anti-debug est
// en C pur et ne peut pas être inclus directement depuis du C++ sans casser
// des dizaines de tests/casts/goto-past-init).
extern "C" {
    void sentinel_bridge_init(void);
    void sentinel_bridge_cleanup(void);
    void sentinel_bridge_taint(unsigned char* data, unsigned int length);
    void sentinel_bridge_recheck(void);
    void sentinel_bridge_verify(void);
    unsigned long long sentinel_bridge_snapshot(void);
    unsigned int sentinel_bridge_score(void);
    unsigned int sentinel_bridge_checks_run(void);
    unsigned int sentinel_bridge_checks_hit(void);
    int sentinel_bridge_re_detect(void);
    unsigned int sentinel_bridge_redetect_mask(void);
    unsigned int sentinel_bridge_get_hit_flags(void);
    void sentinel_bridge_get_layer_report(char* buf, unsigned int buflen);
}

namespace {
} // namespace

namespace Sentinel {

namespace {
    // Externally-reported threat bits — OR'd into the bridge score
    // consumed by deriveAuthTag. AntiRpmGuard sets a non-zero pattern
    // when it catches an external process reading our memory; from that
    // point every server-bound auth_tag is corrupted and Phase 4 bans.
    std::atomic<uint32_t> g_externalThreatBits{0};
}

void reportExternalThreat(uint32_t bits) {
    g_externalThreatBits.fetch_or(bits);
}

void init() {
    VMP_BEGIN_ULTRA("Sentinel_init");
    sentinel_bridge_init();
    VMP_END();
}

void cleanup() {
    VMP_BEGIN_ULTRA("Sentinel_cleanup");
    sentinel_bridge_cleanup();
    VMP_END();
}

void taint(uint8_t* data, uint32_t length) {
    VMP_BEGIN_ULTRA("Sentinel_taint");
    sentinel_bridge_taint(reinterpret_cast<unsigned char*>(data),
                          static_cast<unsigned int>(length));
    VMP_END();
}

void recheck() {
    VMP_BEGIN_ULTRA("Sentinel_recheck");
    sentinel_bridge_recheck();
    VMP_END();
}

void verify() {
    VMP_BEGIN_ULTRA("Sentinel_verify");
    sentinel_bridge_verify();
    VMP_END();
}

uint64_t snapshot() {
    return static_cast<uint64_t>(sentinel_bridge_snapshot());
}

bool reDetect() {
    return sentinel_bridge_re_detect() != 0;
}

uint32_t reDetectMask() {
    return static_cast<uint32_t>(sentinel_bridge_redetect_mask());
}

uint32_t score() {
    return static_cast<uint32_t>(sentinel_bridge_score());
}

uint32_t checksRun() {
    return static_cast<uint32_t>(sentinel_bridge_checks_run());
}

uint32_t checksHit() {
    return static_cast<uint32_t>(sentinel_bridge_checks_hit());
}

std::string layerReport() {
    char buf[512];
    sentinel_bridge_get_layer_report(buf, sizeof(buf));
    return std::string(buf);
}

uint32_t hitFlags() {
    return static_cast<uint32_t>(sentinel_bridge_get_hit_flags());
}

uint64_t deriveAuthTag(const uint8_t* buf, uint32_t length,
                       const uint8_t salt[16], const uint8_t algoSeed[32],
                       const uint8_t codeFingerprint[32]) {
    VMP_BEGIN_ULTRA("Sentinel_deriveAuthTag");

    uint8_t keyMaterial[32] = {};
    {
        BCRYPT_ALG_HANDLE hSha = nullptr;
        if (BCryptOpenAlgorithmProvider(&hSha, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
            VMP_END();
            return 0;
        }
        BCRYPT_HASH_HANDLE hHashKey = nullptr;
        bool keyOk = false;
        if (BCryptCreateHash(hSha, &hHashKey, nullptr, 0, nullptr, 0, 0) == 0) {
            if (BCryptHashData(hHashKey, const_cast<UCHAR*>(salt), 16, 0) == 0
                && BCryptHashData(hHashKey, const_cast<UCHAR*>(algoSeed), 32, 0) == 0
                && BCryptHashData(hHashKey, const_cast<UCHAR*>(codeFingerprint), 32, 0) == 0
                && BCryptFinishHash(hHashKey, keyMaterial, 32, 0) == 0) {
                keyOk = true;
            }
            BCryptDestroyHash(hHashKey);
        }
        BCryptCloseAlgorithmProvider(hSha, 0);
        if (!keyOk) {
            VMP_END();
            return 0;
        }
    }

    // Score Sentinel actuel — même seuil que sentinel_bridge_taint (< 50 = bruit
    // ambiant sur machine clean, ignoré). Au-delà de 50 = debugger détecté,
    // score inclus dans le HMAC → le serveur (score=0) rejette.
    // g_externalThreatBits ne sont pas filtrés : ce sont des signaux
    // explicites (AntiRpmGuard), pas du bruit timing.
    uint32_t rawScore = sentinel_bridge_score();
    uint32_t score = (rawScore >= 50u ? rawScore : 0u)
                   | g_externalThreatBits.load(std::memory_order_relaxed);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                     BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        VMP_END();
        return 0;
    }

    BCRYPT_HASH_HANDLE hHash = nullptr;
    uint8_t mac[32] = {};
    bool ok = false;
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                         keyMaterial, 32, 0) == 0) {
        if (BCryptHashData(hHash, const_cast<UCHAR*>(buf), length, 0) == 0) {
            uint8_t scoreBytes[4] = {
                static_cast<uint8_t>(score & 0xFF),
                static_cast<uint8_t>((score >> 8) & 0xFF),
                static_cast<uint8_t>((score >> 16) & 0xFF),
                static_cast<uint8_t>((score >> 24) & 0xFF),
            };
            if (BCryptHashData(hHash, scoreBytes, sizeof(scoreBytes), 0) == 0) {
                if (BCryptFinishHash(hHash, mac, 32, 0) == 0) {
                    ok = true;
                }
            }
        }
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!ok) {
        VMP_END();
        return 0;
    }

    // First 8 bytes as little-endian uint64.
    uint64_t tag = 0;
    for (int i = 0; i < 8; ++i) {
        tag |= static_cast<uint64_t>(mac[i]) << (i * 8);
    }
    VMP_END();
    return tag;
}

} // namespace Sentinel

#pragma optimize("", on)
