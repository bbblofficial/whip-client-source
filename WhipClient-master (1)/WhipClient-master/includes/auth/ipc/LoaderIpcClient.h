#pragma once

#include "auth/ErrorCode.h"
#include "auth/session/Session.h"
#include <memory>
#include <string>
#include <cstdint>
#include <windows.h>

using Byte = unsigned char;

struct LoaderConfig {
    SecureValue<32> temporaryClientToken;
    SecureValue<32> clientAttestationKey;
    std::string serverHost;
    uint16_t serverPort;
    std::string hwid;
    int64_t timestamp;

    uint64_t loaderAuthTag;
};

enum class ClientLoadStage {
    Start = 0x60,
    Auth = 0x61,
    Versions = 0x62,
    Mappings = 0x63,
    Hooks = 0x64,
    Complete = 0x65
};

enum class ClientDestructReason {
    User = 0,
    Detected = 1,
    Error = 2,
    SessionExpired = 3
};

class WhipNexus;

class LoaderIpcClient {
    struct Impl;
    std::unique_ptr<Impl> impl_;

public:
    LoaderIpcClient();
    ~LoaderIpcClient();

    VoidResult initialize();
    VoidResult connect(const std::string& host, uint16_t port);
    void disconnect();

    void startIpcThread();

    void stopIpcThread();

    Result<LoaderConfig> receiveConfig(int timeoutMs = 5000);

    VoidResult sendLoadProgress(ClientLoadStage stage, const std::string& message, int percent);

    VoidResult sendHeartbeat(int hooksActive, int errorsCount, bool serverConnected);

    VoidResult sendDestruct(ClientDestructReason reason, const std::string& message);

    bool isConnected() const;
    bool isIpcThreadRunning() const;
};
