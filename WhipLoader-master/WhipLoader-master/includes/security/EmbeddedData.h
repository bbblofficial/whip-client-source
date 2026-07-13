#pragma once

#include "util/Types.h"
#include "util/Result.h"
#include "auth/Credentials.h"

class IEmbeddedDataReader {
public:
    virtual ~IEmbeddedDataReader() = default;

    [[nodiscard]] virtual Result<DownloadId> readDownloadId() = 0;

    [[nodiscard]] virtual VoidResult readProductCode(char* outBuffer, u32 bufferSize) = 0;

    [[nodiscard]] virtual VoidResult readAuthSalt(Byte outSalt[16]) = 0;

    [[nodiscard]] virtual VoidResult readAlgoSeed(Byte outSeed[32]) = 0;

    [[nodiscard]] virtual VoidResult readCodeFingerprint(Byte outFp[32]) = 0;

    [[nodiscard]] virtual bool hasValidData() const noexcept = 0;

    [[nodiscard]] virtual bool hasEmbeddedDownloadId() const noexcept = 0;
};

class WindowsEmbeddedDataReader : public IEmbeddedDataReader {
public:
    WindowsEmbeddedDataReader();
    ~WindowsEmbeddedDataReader() override;

    [[nodiscard]] Result<DownloadId> readDownloadId() override;

    [[nodiscard]] VoidResult readProductCode(char* outBuffer, u32 bufferSize) override;

    [[nodiscard]] VoidResult readAuthSalt(Byte outSalt[16]) override;

    [[nodiscard]] VoidResult readAlgoSeed(Byte outSeed[32]) override;

    [[nodiscard]] VoidResult readCodeFingerprint(Byte outFp[32]) override;

    [[nodiscard]] bool hasValidData() const noexcept override;

    [[nodiscard]] bool hasEmbeddedDownloadId() const noexcept override;

private:
    bool valid;
    DownloadId downloadId;
    i64 timestamp;
    Byte downloadIdSalt[16];
    Byte authSalt[16];
    Byte algoSeed[32];
    Byte codeFingerprint[32];

    bool load();
    bool parseOverlay(const Byte* data);
};

IEmbeddedDataReader* createEmbeddedDataReader();
