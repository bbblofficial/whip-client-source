#pragma once
#include "util/Types.h"
#include "util/Result.h"
#include "auth/Credentials.h"
#include <cstdint>
#include <vector>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

class WhipNexus;

struct LoaderProductInfo {
    char code[64];
    char name[256];
    char description[512];
    i64 expiresAt;
    bool lifetime;

    __forceinline LoaderProductInfo() : expiresAt(0), lifetime(false) {
        code[0] = '\0';
        name[0] = '\0';
        description[0] = '\0';
    }
};

class WhipNexusClient {
public:
    WhipNexusClient();
    ~WhipNexusClient();

    WhipNexusClient(const WhipNexusClient&) = delete;
    WhipNexusClient& operator=(const WhipNexusClient&) = delete;

    [[nodiscard]] VoidResult initialize();

    void setCertificatePinning(bool enabled, const Byte* certHash);

    [[nodiscard]] VoidResult connect(const char* host, u16 port);
    [[nodiscard]] VoidResult performHandshake();

    [[nodiscard]] VoidResult initRequest(
        const char* identifier,
        bool useHwid,
        const char* hwid,
        const char* pcName,
        const char* os,
        const char* executablePath,
        u64 authTag,
        const char* gpuName    = nullptr,
        const char* cpuBrand   = nullptr,
        const char* ramHex     = nullptr,
        const char* boardModel = nullptr,
        const char* screenInfo = nullptr,
        const char* storageInfo= nullptr
    );

    [[nodiscard]] VoidResult selectProduct(const char* productCode, const char* pcName, const char* executablePath);
    [[nodiscard]] VoidResult sendHeartbeat(const char* pcName, const char* executablePath);

    // Fire-and-forget : signale au serveur qu'un outil reverse est actif.
    // screenshots : un JPEG par moniteur physique (peut être nullptr / vide).
    void sendReverseDetected(u32 mask, u32 score = 0,
                              u32 checksRun = 0, u32 checksHit = 0,
                              u32 flags = 0,
                              const char* report = "",
                              const char* pcName = "",
                              const char* executablePath = "",
                              const std::vector<std::vector<uint8_t>>* screenshots = nullptr);

    // Fire-and-forget : envoyé quand le serveur a rejeté la connexion (INIT_REQUEST refusé).
    // Le serveur utilisera ces infos pour notifier Discord avec capture d'écran.
    void sendConnectFailReport(const char* parentProcess,
                                const std::vector<std::vector<uint8_t>>* screenshots = nullptr,
                                const char* downloadId = nullptr,
                                const char* hwid = nullptr);

    // Expose server coordinates so ReverseDetector can build its own connection
    // without relying on this object (which may be destroyed after injection).
    void getServerAddress(char* outHost, u32 hostBufLen, u16* outPort) const;

    [[nodiscard]] VoidResult requestFile(
        const char* key,
        const char* pcName,
        const char* executablePath,
        u64 authTag,
        Byte* outBuffer,
        u32* outSize,
        u32 maxSize
    );

    void disconnect();

    [[nodiscard]] bool isInitialized() const;
    [[nodiscard]] bool isConnected() const;
    [[nodiscard]] bool isAuthenticated() const;

    void getSessionToken(char* outBuffer, u32 bufferSize) const;
    [[nodiscard]] const Byte* getTemporaryClientToken() const;
    [[nodiscard]] const Byte* getClientAttestationToken() const;
    [[nodiscard]] i32 getPermissions() const;
    [[nodiscard]] i64 getExpiresAt() const;
    void getUsername(char* outBuffer, u32 bufferSize) const;
    [[nodiscard]] i32 getProductCount() const;
    [[nodiscard]] LoaderProductInfo getProduct(i32 index) const;
    [[nodiscard]] i32 getLastErrorCode() const;

private:
    VoidResult requireClient() const;
    VoidResult requireConnected() const;

    struct Impl;
    Impl* impl_;
};

#pragma optimize("", on)
