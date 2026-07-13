#pragma once

#include "../util/Types.h"

using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i32 = int32_t;
using i64 = int64_t;

__forceinline void authStrCopy(char* dst, const char* src, u32 dstSize) {
    u32 i = 0;
    if (src) {
        while (src[i] && i < dstSize - 1) { dst[i] = src[i]; i++; }
    }
    dst[i] = '\0';
}

__forceinline bool authStrEq(const char* a, const char* b) {
    if (!a || !b) return a == b;
    while (*a && *b) {
        if (*a != *b) return false;
        a++; b++;
    }
    auto result = *a == *b;
    return result;
}

struct DownloadId {
    Byte data[16];

    DownloadId() { for (int i = 0; i < 16; i++) data[i] = 0; }

    __forceinline bool isValid() const {
        for (int i = 0; i < 16; i++)
            if (data[i]) return true;
        return false;
    }

    __forceinline void toChars(char* out, u32 outSize) const {
        const char hex[] = "0123456789ABCDEF";
        u32 pos = 0;
        for (int i = 0; i < 16 && pos + 2 < outSize; i++) {
            out[pos++] = hex[data[i] >> 4];
            out[pos++] = hex[data[i] & 0x0F];
        }
        if (pos < outSize) out[pos] = '\0';
    }

    __forceinline static DownloadId fromBytes(const Byte* bytes) {
        DownloadId id;
        if (bytes) {
            for (int i = 0; i < 16; i++) id.data[i] = bytes[i];
        }
        return id;
    }

    __forceinline static DownloadId fromString(const char* str) {
        DownloadId id;
        if (!str) return id;

        auto hexVal = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };

        for (int i = 0; i < 16; i++) {
            if (!str[i * 2] || !str[i * 2 + 1]) break;
            int high = hexVal(str[i * 2]);
            int low  = hexVal(str[i * 2 + 1]);
            if (high < 0 || low < 0) return DownloadId{};
            id.data[i] = static_cast<Byte>((high << 4) | low);
        }
        return id;
    }
};

struct MachineInfo {
    char hwid[68];
    char pcName[128];
    char os[64];
    char executablePath[512];
    char gpuName[128];
    char cpuBrand[128];
    char ramHex[32];
    char boardModel[128];
    char screenInfo[128];
    char storageInfo[32];

    MachineInfo() {
        hwid[0] = '\0'; pcName[0] = '\0'; os[0] = '\0'; executablePath[0] = '\0';
        gpuName[0] = '\0'; cpuBrand[0] = '\0'; ramHex[0] = '\0';
        boardModel[0] = '\0'; screenInfo[0] = '\0'; storageInfo[0] = '\0';
    }

    bool isValid() const { return hwid[0] != '\0'; }

    void setHwid(const char* s)          { authStrCopy(hwid, s, sizeof(hwid)); }
    void setPcName(const char* s)        { authStrCopy(pcName, s, sizeof(pcName)); }
    void setOs(const char* s)            { authStrCopy(os, s, sizeof(os)); }
    void setExecutablePath(const char* s){ authStrCopy(executablePath, s, sizeof(executablePath)); }
    void setGpuName(const char* s)       { authStrCopy(gpuName, s, sizeof(gpuName)); }
    void setCpuBrand(const char* s)      { authStrCopy(cpuBrand, s, sizeof(cpuBrand)); }
    void setRamHex(const char* s)        { authStrCopy(ramHex, s, sizeof(ramHex)); }
    void setBoardModel(const char* s)    { authStrCopy(boardModel, s, sizeof(boardModel)); }
    void setScreenInfo(const char* s)    { authStrCopy(screenInfo, s, sizeof(screenInfo)); }
    void setStorageInfo(const char* s)   { authStrCopy(storageInfo, s, sizeof(storageInfo)); }
};

struct AuthPayload {
    DownloadId downloadId;
    MachineInfo machine;
    char productCode[64];
    i64 timestamp;

    AuthPayload() : timestamp(0) { productCode[0] = '\0'; }

    void setProductCode(const char* s) { authStrCopy(productCode, s, sizeof(productCode)); }

    __forceinline bool isValid() const {
        auto result = downloadId.isValid() && machine.isValid() && productCode[0] != '\0';
        return result;
    }
};
