#pragma once

#include "../util/Types.h"
#include "../util/Result.h"
#include "BuildConfig.h"

#include <string>
#include <vector>

struct ServerConfig {
    std::string host = "127.0.0.1";
    uint16_t port = BuildConfig::serverPort;
    bool useTls = true;
    Duration connectionTimeout = std::chrono::seconds(30);
    Duration requestTimeout = std::chrono::seconds(15);
    int maxRetries = 3;
    Duration retryDelay = std::chrono::seconds(5);
};

struct TlsConfig {
    static constexpr bool enableCertificatePinning = true;

    // Hash SHA-256 du certificat serveur (hardcodé)
    // Pour obtenir le hash: démarrer WhipServer et copier depuis les logs
    // Pour convertir: python tools/convert_cert_hash.py <hash>
    static constexpr Byte pinnedCertificateHash[32] = {
        0xb6, 0x9e, 0x14, 0x43, 0x48, 0x63, 0x53, 0x00,
        0x2c, 0x88, 0x78, 0x43, 0xf3, 0xfe, 0x20, 0x53,
        0xc0, 0x28, 0x73, 0x65, 0x88, 0x5d, 0x69, 0xb7,
        0x9d, 0xc8, 0x95, 0xed, 0xc2, 0x07, 0xb2, 0xfa
    };

    bool verifyHostname = true;
};

struct InjectionConfig {
    std::string targetProcessName = "game.exe";
    Duration processWaitTimeout = std::chrono::minutes(5);
    Duration processCheckInterval = std::chrono::seconds(1);
    bool eraseHeaders = true;           // Effacer PE headers après injection
    bool useTlsCallbacks = true;        // Exécuter TLS callbacks
};

struct HeartbeatConfig {
    Duration interval = std::chrono::seconds(30);
    Duration timeout = std::chrono::seconds(60);
    int maxMissed = 2;                  // Heartbeats manqués avant déconnexion
};

struct IpcConfig {
    std::string host = "127.0.0.1";
    uint16_t portRangeStart = 49152;    // Ports dynamiques
    uint16_t portRangeEnd = 65535;
    Duration connectionTimeout = std::chrono::seconds(10);
};

struct SecurityConfig {
    bool enableAntiDebug = false;
    bool enableIntegrityCheck = true;
    bool clearSecretsOnExit = true;
    Duration secretsClearDelay = std::chrono::seconds(1);
};

struct UIConfig {
    bool startMinimized = false;
    bool minimizeToTray = true;
    bool showNotifications = true;
    bool rememberCredentials = false;   // Jamais en Zero Trust strict
};


struct LoaderConfig {
    ServerConfig server;
    TlsConfig tls;
    InjectionConfig injection;
    HeartbeatConfig heartbeat;
    IpcConfig ipc;
    SecurityConfig security;
    UIConfig ui;

    std::string version = "1.0.0";
    std::string buildId;

    [[nodiscard]] static Result<LoaderConfig> loadFromFile(const std::string& path);
    [[nodiscard]] VoidResult saveToFile(const std::string& path) const;

    [[nodiscard]] bool validate() const;
    [[nodiscard]] std::vector<std::string> getValidationErrors() const;
};

class ConfigManager {
public:
    static ConfigManager& instance();

    [[nodiscard]] VoidResult initialize(const std::string& configPath = "");
    [[nodiscard]] const LoaderConfig& config() const noexcept;
    [[nodiscard]] LoaderConfig& mutableConfig() noexcept;

    void reload();
    void save();

private:
    ConfigManager() = default;

    LoaderConfig config_;
    std::string configPath_;
};