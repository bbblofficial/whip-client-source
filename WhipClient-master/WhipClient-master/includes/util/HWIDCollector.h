#pragma once

#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <bcrypt.h>
#include <cstdio>
#include <whipsyscall/WhipSysCall.h>

#pragma comment(lib, "bcrypt.lib")

#ifdef VMP
#include "VMProtectSDK.h"
#endif

static const char s_hwid_hex[] = "0123456789abcdef";

struct HWIDComponents {
    char cpuId[68];
    char boardSerial[128];
    char machineGuid[128];
    char biosSerial[128];
    char gpuId[128];
    char ramInfo[32];
    char tpmId[128];
};

static inline SyscallResolver& hwid_GetResolver() {
    static SyscallResolver s;
    static bool init = s.Init();
    (void)init;
    return s;
}

static inline SyscallWrappers& hwid_GetWrappers() {
    static SyscallWrappers w(&hwid_GetResolver());
    return w;
}

static inline void hwid_NtClose(HANDLE h) {
    if (!h) return;
    WORD ssn; PVOID addr;
    if (hwid_GetResolver().ResolveByName("NtClose", ssn, addr))
        SyscallInvoker::Invoke(ssn, h);
}

static inline HANDLE hwid_NtOpenRegKey(const wchar_t* ntPath) {
    WORD ssn; PVOID addr;
    if (!hwid_GetResolver().ResolveByName("NtOpenKey", ssn, addr)) return nullptr;

    SIZE_T len = 0; while (ntPath[len]) len++;
    UNICODE_STRING ks;
    ks.Length        = static_cast<USHORT>(len * sizeof(wchar_t));
    ks.MaximumLength = ks.Length + static_cast<USHORT>(sizeof(wchar_t));
    ks.Buffer        = const_cast<PWSTR>(ntPath);

    OBJECT_ATTRIBUTES oa = {};
    oa.Length     = sizeof(oa);
    oa.ObjectName = &ks;
    oa.Attributes = 0x40;

    HANDLE hKey = nullptr;
    NTSTATUS s = SyscallInvoker::Invoke(
        ssn,
        &hKey,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0x20019)),
        &oa
    );
    return NT_SUCCESS(s) ? hKey : nullptr;
}

static inline bool hwid_NtQueryRegSZ(HANDLE hKey, const wchar_t* valueName, char* out, DWORD outSize) {
    WORD ssn; PVOID addr;
    if (!hwid_GetResolver().ResolveByName("NtQueryValueKey", ssn, addr)) return false;

    SIZE_T vl = 0; while (valueName[vl]) vl++;
    UNICODE_STRING vs;
    vs.Length        = static_cast<USHORT>(vl * sizeof(wchar_t));
    vs.MaximumLength = vs.Length + static_cast<USHORT>(sizeof(wchar_t));
    vs.Buffer        = const_cast<PWSTR>(valueName);

    ULONG needed = 0;
    SyscallInvoker::Invoke(ssn, hKey, &vs,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(2)),
        nullptr,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0)),
        &needed);
    if (needed == 0) needed = 1024;

    unsigned char buf[1024] = {};
    if (needed > sizeof(buf)) needed = sizeof(buf);
    ULONG ret = 0;
    NTSTATUS s = SyscallInvoker::Invoke(ssn, hKey, &vs,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(2)),
        buf,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(needed)),
        &ret);
    if (!NT_SUCCESS(s)) return false;

    ULONG type    = *reinterpret_cast<ULONG*>(buf + 4);
    ULONG dataLen = *reinterpret_cast<ULONG*>(buf + 8);
    if (type != 1  || dataLen < 2) return false;

    const wchar_t* wstr = reinterpret_cast<const wchar_t*>(buf + 12);
    ULONG wlen = dataLen / sizeof(wchar_t);
    if (wlen > 0 && wstr[wlen - 1] == L'\0') wlen--;
    if (wlen == 0) return false;

    int n = WideCharToMultiByte(CP_UTF8, 0, wstr, (int)wlen, nullptr, 0, nullptr, nullptr);
    if (n <= 0 || static_cast<DWORD>(n) >= outSize) return false;
    WideCharToMultiByte(CP_UTF8, 0, wstr, (int)wlen, out, n, nullptr, nullptr);
    out[n] = '\0';
    return true;
}

#pragma optimize("", off)

inline void collectCpuId(char* out, DWORD outSize) {
    int cpuInfo0[4] = {0};
    int cpuInfo1[4] = {0};
    __cpuid(cpuInfo0, 0);
    __cpuid(cpuInfo1, 1);
    if (outSize < 49) { if (outSize > 0) out[0] = '\0'; return; }
    DWORD pos = 0;

    for (int i = 0; i < 4; i++) {
        DWORD v = (DWORD)cpuInfo0[i];
        for (int j = 7; j >= 0; j--) {
            out[pos++] = s_hwid_hex[(v >> (j * 4)) & 0xF];
        }
    }

    for (int i : {0, 3}) {
        DWORD v = (DWORD)cpuInfo1[i];
        for (int j = 7; j >= 0; j--) {
            out[pos++] = s_hwid_hex[(v >> (j * 4)) & 0xF];
        }
    }
    out[pos] = '\0';
}

inline void collectGpuId(char* out, DWORD outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return; }
    out[0] = '\0';

    HANDLE hKey = hwid_NtOpenRegKey(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class"
        L"\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000");
    if (!hKey) return;
    if (!hwid_NtQueryRegSZ(hKey, L"MatchingDeviceId", out, outSize)) {
        hwid_NtQueryRegSZ(hKey, L"DriverDesc", out, outSize);
    }
    hwid_NtClose(hKey);
}

inline void collectRamInfo(char* out, DWORD outSize) {
    if (outSize < 17) { if (outSize > 0) out[0] = '\0'; return; }
    out[0] = '\0';

    WORD ssn; PVOID addr;
    if (!hwid_GetResolver().ResolveByName("NtQuerySystemInformation", ssn, addr)) return;

    struct { ULONG Reserved; ULONG TimerResolution; ULONG PageSize; ULONG NumberOfPhysicalPages;
             ULONG LowestPhysicalPageNumber; ULONG HighestPhysicalPageNumber;
             ULONG AllocationGranularity; ULONG_PTR MinimumUserModeAddress;
             ULONG_PTR MaximumUserModeAddress; ULONG_PTR ActiveProcessorsAffinityMask;
             CCHAR NumberOfProcessors; } sysInfo = {};

    ULONG retLen = 0;
    NTSTATUS s = SyscallInvoker::Invoke(ssn,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0)),
        &sysInfo,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(sysInfo))),
        &retLen);
    if (!NT_SUCCESS(s)) return;

    uint64_t totalRam = (uint64_t)sysInfo.NumberOfPhysicalPages * (uint64_t)sysInfo.PageSize;
    for (int j = 15; j >= 0; j--) {
        out[15 - j] = s_hwid_hex[(totalRam >> (j * 4)) & 0xF];
    }
    out[16] = '\0';
}

inline void collectTpmId(char* out, DWORD outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return; }
    out[0] = '\0';

    HANDLE hKey = hwid_NtOpenRegKey(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI");
    if (!hKey) return;
    if (!hwid_NtQueryRegSZ(hKey, L"WindowsAIKHash", out, outSize)) {
        hwid_NtQueryRegSZ(hKey, L"ManufacturerId", out, outSize);
    }
    hwid_NtClose(hKey);
}

inline void collectBoardSerial(char* out, DWORD outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return; }
    out[0] = '\0';

    HANDLE hKey = hwid_NtOpenRegKey(
        L"\\Registry\\Machine\\HARDWARE\\Description\\System\\BIOS");
    if (!hKey) return;
    if (!hwid_NtQueryRegSZ(hKey, L"BaseBoardSerialNumber", out, outSize)) {

        hwid_NtQueryRegSZ(hKey, L"BaseBoardProduct", out, outSize);
    }
    hwid_NtClose(hKey);
}

inline void collectMachineGuid(char* out, DWORD outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return; }
    out[0] = '\0';

    HANDLE hKey = hwid_NtOpenRegKey(
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
    if (!hKey) return;
    hwid_NtQueryRegSZ(hKey, L"MachineGuid", out, outSize);
    hwid_NtClose(hKey);
}

inline void collectBiosSerial(char* out, DWORD outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return; }
    out[0] = '\0';

    HANDLE hKey = hwid_NtOpenRegKey(
        L"\\Registry\\Machine\\HARDWARE\\Description\\System\\BIOS");
    if (!hKey) return;
    hwid_NtQueryRegSZ(hKey, L"SystemSerialNumber", out, outSize);
    hwid_NtClose(hKey);
}

inline bool computeHwidHash(const HWIDComponents& hwid, char* outHash, DWORD outHashSize) {
    char combined[700] = {};
    DWORD pos = 0;

    const char* parts[] = { hwid.cpuId, hwid.boardSerial, hwid.machineGuid, hwid.biosSerial, hwid.gpuId, hwid.ramInfo, hwid.tpmId };
    for (int p = 0; p < 7; p++) {
        const char* s = parts[p];
        while (*s && pos < sizeof(combined) - 1) combined[pos++] = *s++;
    }
    combined[pos] = '\0';

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD cbObjectLen = 0;
    DWORD cbHash = 0;
    DWORD cbResult = 0;
    BYTE hash[32] = {};
    BYTE hashObject[512] = {};

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return false;

    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbObjectLen, sizeof(DWORD), &cbResult, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbResult, 0);

    if (cbObjectLen > sizeof(hashObject)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    if (BCryptCreateHash(hAlg, &hHash, hashObject, cbObjectLen, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCryptHashData(hHash, (PBYTE)combined, pos, 0);
    BCryptFinishHash(hHash, hash, cbHash, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (outHashSize < 65) return false;
    for (DWORD i = 0; i < 32; i++) {
        outHash[i * 2]     = s_hwid_hex[(hash[i] >> 4) & 0xF];
        outHash[i * 2 + 1] = s_hwid_hex[hash[i] & 0xF];
    }
    outHash[64] = '\0';
    return true;
}

// Human-readable GPU display name (DriverDesc, e.g. "NVIDIA GeForce RTX 4090").
// Separate from collectGpuId so the HWID hash is never affected.
inline void collectGpuName(char* out, DWORD outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return; }
    out[0] = '\0';
    HANDLE hKey = hwid_NtOpenRegKey(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class"
        L"\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000");
    if (!hKey) return;
    hwid_NtQueryRegSZ(hKey, L"DriverDesc", out, outSize);
    hwid_NtClose(hKey);
}

// CPU brand string (e.g. "Intel(R) Core(TM) i9-14900K CPU @ 3.20GHz").
inline void collectCpuBrand(char* out, DWORD outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return; }
    out[0] = '\0';
    HANDLE hKey = hwid_NtOpenRegKey(
        L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0");
    if (!hKey) return;
    hwid_NtQueryRegSZ(hKey, L"ProcessorNameString", out, outSize);
    hwid_NtClose(hKey);
}

static inline bool hwid_boardModelIsPlaceholder(const char* s) {
    if (!s || !s[0]) return true;
    const char* ph[] = { "System Product Name", "To be filled by O.E.M.", "Default string", "Not Applicable", nullptr };
    for (int i = 0; ph[i]; i++) { const char* a = s, *b = ph[i]; while (*a && *b && *a == *b) { a++; b++; } if (!*b) return true; }
    return false;
}

// System family / product line (e.g. "Legion T5 26AMR5", "ROG STRIX G17").
inline void collectBoardModel(char* out, DWORD outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return; }
    out[0] = '\0';
    HANDLE hKey = hwid_NtOpenRegKey(L"\\Registry\\Machine\\HARDWARE\\Description\\System\\BIOS");
    if (!hKey) return;
    // 1. SystemFamily (most human-readable: "Legion T5 26AMR5")
    if (hwid_NtQueryRegSZ(hKey, L"SystemFamily", out, outSize) && !hwid_boardModelIsPlaceholder(out)) {
        hwid_NtClose(hKey); return;
    }
    out[0] = '\0';
    // 2. SystemProductName
    if (hwid_NtQueryRegSZ(hKey, L"SystemProductName", out, outSize) && !hwid_boardModelIsPlaceholder(out)) {
        hwid_NtClose(hKey); return;
    }
    out[0] = '\0';
    // 3. Manufacturer + BaseBoardProduct
    char mfr[128] = {}, prod[128] = {};
    hwid_NtQueryRegSZ(hKey, L"BaseBoardManufacturer", mfr, sizeof(mfr));
    hwid_NtQueryRegSZ(hKey, L"BaseBoardProduct", prod, sizeof(prod));
    if (prod[0]) {
        if (mfr[0]) snprintf(out, outSize, "%s %s", mfr, prod);
        else { DWORD i = 0; while (prod[i] && i < outSize-1) out[i++] = prod[i]; out[i] = '\0'; }
    }
    hwid_NtClose(hKey);
}

struct hwid_ScreenCtx { char* out; DWORD sz; DWORD pos; };
static inline BOOL CALLBACK hwid_screenEnumProc(HMONITOR hm, HDC, LPRECT, LPARAM lp) {
    auto* ctx = reinterpret_cast<hwid_ScreenCtx*>(lp);
    MONITORINFOEXA mi = {}; mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoA(hm, reinterpret_cast<LPMONITORINFO>(&mi))) return TRUE;
    DEVMODEA dm = {}; dm.dmSize = sizeof(dm);
    if (!EnumDisplaySettingsA(mi.szDevice, ENUM_CURRENT_SETTINGS, &dm)) return TRUE;
    if (!dm.dmPelsWidth || !dm.dmPelsHeight) return TRUE;
    char buf[32]; int n;
    if (dm.dmDisplayFrequency > 1)
        n = snprintf(buf, sizeof(buf), "%lux%lu@%luHz", dm.dmPelsWidth, dm.dmPelsHeight, dm.dmDisplayFrequency);
    else
        n = snprintf(buf, sizeof(buf), "%lux%lu", dm.dmPelsWidth, dm.dmPelsHeight);
    if (n <= 0) return TRUE;
    if (ctx->pos > 0 && ctx->pos + 2 < ctx->sz) { ctx->out[ctx->pos++] = ','; ctx->out[ctx->pos++] = ' '; }
    DWORD copy = (DWORD)n;
    if (ctx->pos + copy + 1 >= ctx->sz) copy = ctx->sz - ctx->pos - 1;
    for (DWORD j = 0; j < copy; j++) ctx->out[ctx->pos++] = buf[j];
    ctx->out[ctx->pos] = '\0';
    return TRUE;
}

// All active monitors via EnumDisplayMonitors: "1920x1080@165Hz, 2560x1440@60Hz".
inline void collectScreenInfo(char* out, DWORD outSize) {
    if (outSize < 8) { if (outSize > 0) out[0] = '\0'; return; }
    out[0] = '\0';
    hwid_ScreenCtx ctx = { out, outSize, 0 };
    EnumDisplayMonitors(nullptr, nullptr, hwid_screenEnumProc, reinterpret_cast<LPARAM>(&ctx));
}

// Primary disk (C:) total size in Go (e.g. "512 Go").
inline void collectStorageInfo(char* out, DWORD outSize) {
    if (outSize < 4) { if (outSize > 0) out[0] = '\0'; return; }
    out[0] = '\0';
    ULARGE_INTEGER total = {}, free2 = {}, avail = {};
    if (!GetDiskFreeSpaceExA("C:\\", &avail, &total, &free2)) return;
    unsigned long long gb = (unsigned long long)(total.QuadPart / (1024ULL * 1024 * 1024));
    snprintf(out, outSize, "%llu Go", gb);
}

// Aggregates all display-only hardware info alongside the HWID hash.
// HWID hash is NOT affected — display fields are collected independently.
struct HWIDDisplayInfo {
    char gpuName[128];
    char cpuBrand[128];
    char ramHex[32];
    char boardModel[128];
    char screenInfo[128];
    char storageInfo[32];
};

inline bool collectHwidWithInfo(char* outHash, DWORD hashSize, HWIDDisplayInfo& info) {
    HWIDComponents components = {};
    collectCpuId(components.cpuId, sizeof(components.cpuId));
    collectBoardSerial(components.boardSerial, sizeof(components.boardSerial));
    collectMachineGuid(components.machineGuid, sizeof(components.machineGuid));
    collectBiosSerial(components.biosSerial, sizeof(components.biosSerial));
    collectGpuId(components.gpuId, sizeof(components.gpuId));
    collectRamInfo(components.ramInfo, sizeof(components.ramInfo));
    collectTpmId(components.tpmId, sizeof(components.tpmId));
    bool result = computeHwidHash(components, outHash, hashSize);
    collectGpuName(info.gpuName, sizeof(info.gpuName));
    collectCpuBrand(info.cpuBrand, sizeof(info.cpuBrand));
    DWORD i = 0;
    while (components.ramInfo[i] && i < sizeof(info.ramHex) - 1) { info.ramHex[i] = components.ramInfo[i]; i++; }
    info.ramHex[i] = '\0';
    collectBoardModel(info.boardModel, sizeof(info.boardModel));
    collectScreenInfo(info.screenInfo, sizeof(info.screenInfo));
    collectStorageInfo(info.storageInfo, sizeof(info.storageInfo));
    return result;
}

inline bool collectHwid(char* out, DWORD outSize) {
#ifdef VMP
    VMProtectBeginUltra("collectHwid");
#endif
    HWIDComponents components = {};
    collectCpuId(components.cpuId, sizeof(components.cpuId));
    collectBoardSerial(components.boardSerial, sizeof(components.boardSerial));
    collectMachineGuid(components.machineGuid, sizeof(components.machineGuid));
    collectBiosSerial(components.biosSerial, sizeof(components.biosSerial));
    collectGpuId(components.gpuId, sizeof(components.gpuId));
    collectRamInfo(components.ramInfo, sizeof(components.ramInfo));
    collectTpmId(components.tpmId, sizeof(components.tpmId));
    bool result = computeHwidHash(components, out, outSize);
#ifdef VMP
    VMProtectEnd();
#endif
    return result;
}

#pragma optimize("", on)
