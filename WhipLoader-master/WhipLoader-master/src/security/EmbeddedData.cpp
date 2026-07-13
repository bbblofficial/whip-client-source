#pragma optimize("", off)
#include "security/EmbeddedData.h"
#include "auth/Credentials.h"

#include <Windows.h>
#include <cstring>

namespace {
    constexpr Byte OVERLAY_MAGIC[4] = {'W', 'H', 'I', 'P'};
    constexpr u16 OVERLAY_VERSION = 5;
    // v4 (142) + obfCodeFingerprint[32] + codeFingerprintKey[32] = 206
    constexpr u32 OVERLAY_SIZE = 206;
    constexpr u32 AUTH_SALT_BYTES = 16;
    constexpr u32 ALGO_SEED_BYTES = 32;
    constexpr u32 CODE_FINGERPRINT_BYTES = 32;
    constexpr u32 MAX_SEARCH_SIZE = 8192;

    // When the loader is manual-mapped (WhipMmap), GetModuleFileNameA(nullptr)
    // returns the HOST exe (Lunar, SelfInjectTest, ...) which has no WHIP
    // overlay — and worse, may coincidentally contain the "WHIP" magic in its
    // string table, producing garbage parsed as a download id. WhipMmap stashes
    // the temp-file path of the original DLL in WHIPLOADER_IMAGE_PATH before
    // dispatching DllMain; we prefer that when set.
    bool getExecutablePath(char* outPath, u32 maxLen) {
        DWORD envLen = GetEnvironmentVariableA("WHIPLOADER_IMAGE_PATH", outPath, maxLen);
        if (envLen > 0 && envLen < maxLen) {
            outPath[envLen] = '\0';
            return true;
        }
        DWORD size = GetModuleFileNameA(nullptr, outPath, maxLen);
        if (size == 0 || size == maxLen) {
            return false;
        }
        outPath[size] = '\0';
        return true;
    }
}

WindowsEmbeddedDataReader::WindowsEmbeddedDataReader()
    : valid(false), downloadId{}, timestamp(0), downloadIdSalt{}, authSalt{}, algoSeed{}, codeFingerprint{} {
    for (u32 i = 0; i < 16; ++i) {
        downloadIdSalt[i] = 0;
        authSalt[i] = 0;
    }
    for (u32 i = 0; i < ALGO_SEED_BYTES; ++i) {
        algoSeed[i] = 0;
    }
    for (u32 i = 0; i < CODE_FINGERPRINT_BYTES; ++i) {
        codeFingerprint[i] = 0;
    }
    load();
}

WindowsEmbeddedDataReader::~WindowsEmbeddedDataReader() = default;

bool WindowsEmbeddedDataReader::load() {
    char exePath[MAX_PATH];
    if (!getExecutablePath(exePath, sizeof(exePath))) {
        return false;
    }

    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return false;
    }

    if (fileSize.QuadPart < OVERLAY_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    // Only read EXACTLY the overlay-sized tail. The previous design scanned
    // the last 8KB for the WHIP magic, which produced false positives when
    // the binary contained an `OVERLAY_MAGIC[4] = {'W','H','I','P'}`
    // constexpr in .rdata that ended up inside the search window — observed
    // in manual-mapped builds where no real overlay is present. A genuine
    // overlay is always at the very last OVERLAY_SIZE bytes of the file, so
    // restricting the read to that exact range eliminates the false-positive
    // entirely while still finding any legitimate stamped overlay.
    Byte* buffer = new Byte[OVERLAY_SIZE];

    LARGE_INTEGER seekPos;
    seekPos.QuadPart = fileSize.QuadPart - OVERLAY_SIZE;
    if (!SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN)) {
        delete[] buffer;
        CloseHandle(hFile);
        return false;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, OVERLAY_SIZE, &bytesRead, nullptr) || bytesRead != OVERLAY_SIZE) {
        delete[] buffer;
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    bool found = false;
    if (memcmp(buffer, OVERLAY_MAGIC, 4) == 0) {
        found = parseOverlay(buffer);
    }

    delete[] buffer;
    return found;
}

bool WindowsEmbeddedDataReader::parseOverlay(const Byte* data) {
    if (memcmp(data, OVERLAY_MAGIC, 4) != 0) {
        return false;
    }
    data += 4;

    u16 version = data[0] | (data[1] << 8);
    if (version != OVERLAY_VERSION) {
        return false;
    }
    data += 2;

    const Byte* obfuscatedDownloadId = data;
    data += 16;

    timestamp = 0;
    for (int i = 0; i < 8; ++i) {
        timestamp |= static_cast<i64>(data[i]) << (i * 8);
    }
    data += 8;

    memcpy(downloadIdSalt, data, 16);
    data += 16;

    Byte deobfuscatedDownloadId[16];
    for (int i = 0; i < 16; i++) {
        deobfuscatedDownloadId[i] = obfuscatedDownloadId[i] ^ downloadIdSalt[i];
    }
    downloadId = DownloadId::fromBytes(deobfuscatedDownloadId);

    const Byte* obfuscatedAuthSalt = data;
    data += AUTH_SALT_BYTES;

    const Byte* authSaltKey = data;
    data += AUTH_SALT_BYTES;
    for (u32 i = 0; i < AUTH_SALT_BYTES; ++i) {
        authSalt[i] = obfuscatedAuthSalt[i] ^ authSaltKey[i];
    }

    const Byte* obfuscatedAlgoSeed = data;
    data += ALGO_SEED_BYTES;

    const Byte* algoSeedKey = data;
    data += ALGO_SEED_BYTES;
    for (u32 i = 0; i < ALGO_SEED_BYTES; ++i) {
        algoSeed[i] = obfuscatedAlgoSeed[i] ^ algoSeedKey[i];
    }

    const Byte* obfuscatedCodeFp = data;
    data += CODE_FINGERPRINT_BYTES;

    const Byte* codeFpKey = data;
    for (u32 i = 0; i < CODE_FINGERPRINT_BYTES; ++i) {
        codeFingerprint[i] = obfuscatedCodeFp[i] ^ codeFpKey[i];
    }

    valid = downloadId.isValid();
    return valid;
}

Result<DownloadId> WindowsEmbeddedDataReader::readDownloadId() {
    if (!valid) {
        return Result<DownloadId>::err(ErrorCode::NotFound, "No embedded data found");
    }
    return Result<DownloadId>::ok(downloadId);
}

VoidResult WindowsEmbeddedDataReader::readProductCode(char* outBuffer, u32 bufferSize) {
    return VoidResult::err(ErrorCode::NotFound, "Product code not embedded");
}

VoidResult WindowsEmbeddedDataReader::readAuthSalt(Byte outSalt[16]) {
    if (!valid) {
        return VoidResult::err(ErrorCode::NotFound, "No embedded data found");
    }
    memcpy(outSalt, authSalt, AUTH_SALT_BYTES);
    return VoidResult::ok();
}

VoidResult WindowsEmbeddedDataReader::readAlgoSeed(Byte outSeed[32]) {
    if (!valid) {
        return VoidResult::err(ErrorCode::NotFound, "No embedded data found");
    }
    memcpy(outSeed, algoSeed, ALGO_SEED_BYTES);
    return VoidResult::ok();
}

VoidResult WindowsEmbeddedDataReader::readCodeFingerprint(Byte outFp[32]) {
    if (!valid) {
        return VoidResult::err(ErrorCode::NotFound, "No embedded data found");
    }
    memcpy(outFp, codeFingerprint, CODE_FINGERPRINT_BYTES);
    return VoidResult::ok();
}

bool WindowsEmbeddedDataReader::hasValidData() const noexcept {
    return valid;
}

bool WindowsEmbeddedDataReader::hasEmbeddedDownloadId() const noexcept {
    return valid;
}

IEmbeddedDataReader* createEmbeddedDataReader() {
    return new WindowsEmbeddedDataReader();
}

#pragma optimize("", on)
