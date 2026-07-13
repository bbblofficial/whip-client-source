#pragma once
#include "util/Result.h"
#include <whipnexus/WhipNexusServer.h>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

enum class ClientLoadStage {
    Start = 0x60,
    Auth = 0x61,
    Versions = 0x62,
    Mappings = 0x63,
    Hooks = 0x64,
    Complete = 0x65
};

struct ClientLoadProgress {
    ClientLoadStage stage;
    char message[512];
    int percent;
};

struct ClientHeartbeatInfo {
    int hooksActive;
    int errorsCount;
    bool serverConnected;
};

enum class ClientDestructReason {
    User = 0,
    Detected = 1,
    Error = 2,
    SessionExpired = 3
};

typedef void (*OnClientLoadProgress)(const ClientLoadProgress* progress);
typedef void (*OnClientHeartbeat)(const ClientHeartbeatInfo* info);
typedef void (*OnClientDestruct)(ClientDestructReason reason, const char* message);

class LoaderIpcServer {
public:
    LoaderIpcServer();
    ~LoaderIpcServer();

    [[nodiscard]] VoidResult initialize();
    [[nodiscard]] VoidResult start();
    void stop();

    [[nodiscard]] u16 getPort() const;
    [[nodiscard]] bool isRunning() const;

    [[nodiscard]] VoidResult sendConfig(
        const byte* temporaryClientToken,
        const byte* clientAttestationKey,
        const char* serverHost,
        u16 serverPort,
        const char* hwid,
        u64 authTag
    );

    void setOnLoadProgress(OnClientLoadProgress callback);
    void setOnHeartbeat(OnClientHeartbeat callback);
    void setOnDestruct(OnClientDestruct callback);

private:
    struct Impl;
    Impl* impl_;
};

#pragma optimize("", on)
