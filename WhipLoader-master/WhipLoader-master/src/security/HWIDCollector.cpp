#pragma optimize("", off)
#include "security/HWIDCollector.h"

#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <whipsyscall/WhipSysCall.h>
#include <intrin.h>

#include "security/xor.h"

#pragma comment(lib, "bcrypt.lib")

#ifdef WHIP_BYPASS_MODE
// In bypass mode the loader is mapped into Lunar (Electron/Chromium). Chromium
// rewrites half the ntdll Nt*/Zw* stubs to redirect them through its sandbox
// broker, which breaks SyscallResolver's SSN extraction and the Halo's Gate
// gap-fill (alphabetical clusters of hooked stubs produce wrong interpolated
// SSNs → STATUS_INVALID_SYSTEM_SERVICE). The plain Win32 advapi32 paths go
// through the broker properly and read the real registry / system info.
#pragma comment(lib, "advapi32.lib")

namespace {
    bool Win32QueryRegSZ(HKEY hRoot, const wchar_t* subKey,
                         const wchar_t* valueName, char* out, DWORD outSize) {
        HKEY hKey = nullptr;
        LSTATUS s = RegOpenKeyExW(hRoot, subKey, 0,
                                  KEY_READ | KEY_WOW64_64KEY, &hKey);
        if (s != ERROR_SUCCESS || !hKey) return false;

        wchar_t wbuf[1024] = {};
        DWORD type = 0, cb = sizeof(wbuf);
        s = RegQueryValueExW(hKey, valueName, nullptr, &type,
                             reinterpret_cast<LPBYTE>(wbuf), &cb);
        RegCloseKey(hKey);
        if (s != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
            return false;

        // cb = bytes incl. null terminator(s); convert to wchar count, trim null.
        DWORD wlen = cb / sizeof(wchar_t);
        if (wlen > 0 && wbuf[wlen - 1] == L'\0') wlen--;
        if (wlen == 0) return false;

        int n = WideCharToMultiByte(CP_UTF8, 0, wbuf, (int)wlen,
                                    nullptr, 0, nullptr, nullptr);
        if (n <= 0 || static_cast<DWORD>(n) >= outSize) return false;
        WideCharToMultiByte(CP_UTF8, 0, wbuf, (int)wlen, out, n,
                            nullptr, nullptr);
        out[n] = '\0';
        return true;
    }
}
#endif // WHIP_BYPASS_MODE

static const char s_hex[] = "0123456789abcdef";

// ─── Singleton resolver + wrappers ───────────────────────────────────────────
static SyscallResolver& GetResolver() {
    static SyscallResolver s_res;
    static bool s_init = s_res.Init();
    (void)s_init;
    return s_res;
}
static SyscallWrappers& GetWrappers() {
    static SyscallWrappers s_wrap(&GetResolver());
    return s_wrap;
}

// ─── NT helpers ───────────────────────────────────────────────────────────────

static HANDLE NtOpenRegKey(const wchar_t* ntPath) {
    WORD ssn; PVOID addr;
    if (!GetResolver().ResolveByName("NtOpenKey", ssn, addr)) return nullptr;

    SIZE_T len = 0; while (ntPath[len]) len++;
    UNICODE_STRING ks;
    ks.Length        = static_cast<USHORT>(len * sizeof(wchar_t));
    ks.MaximumLength = ks.Length + static_cast<USHORT>(sizeof(wchar_t));
    ks.Buffer        = const_cast<PWSTR>(ntPath);

    OBJECT_ATTRIBUTES oa = {};
    oa.Length     = sizeof(oa);
    oa.ObjectName = &ks;
    oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE

    HANDLE hKey = nullptr;
    NTSTATUS s = SyscallInvoker::Invoke(
        ssn,
        &hKey,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0x20019)), // KEY_READ
        &oa
    );
    return NT_SUCCESS(s) ? hKey : nullptr;
}

// Query REG_SZ value → UTF-8 into char buffer
static bool NtQueryRegSZ(HANDLE hKey, const wchar_t* valueName, char* out, DWORD outSize) {
    WORD ssn; PVOID addr;
    if (!GetResolver().ResolveByName("NtQueryValueKey", ssn, addr)) return false;

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
    if (type != 1 /* REG_SZ */ || dataLen < 2) return false;

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

// ─── Hex helpers ─────────────────────────────────────────────────────────────

static void u32ToHex(DWORD val, char* out) {
    for (int j = 7; j >= 0; j--) {
        out[7 - j] = s_hex[(val >> (j * 4)) & 0xF];
    }
}

// ─── Collectors ──────────────────────────────────────────────────────────────

bool WindowsHWIDCollector::collectCpuId(char* out, u32 outSize) {
    int info0[4] = {0};
    int info1[4] = {0};
    __cpuid(info0, 0); // Vendor string
    __cpuid(info1, 1); // Processor signature: stepping, model, family, features

    // Leaf 0 (4 DWORDs = 32 chars) + leaf 1 EAX+EDX (2 DWORDs = 16 chars) = 48 chars + null
    if (outSize < 49) { if (outSize > 0) out[0] = '\0'; return false; }

    DWORD pos = 0;
    for (int i = 0; i < 4; i++) {
        u32ToHex((DWORD)info0[i], out + pos);
        pos += 8;
    }
    u32ToHex((DWORD)info1[0], out + pos); pos += 8; // EAX (signature)
    u32ToHex((DWORD)info1[3], out + pos); pos += 8; // EDX (features)
    out[pos] = '\0';
    return true;
}

bool WindowsHWIDCollector::collectGpuId(char* out, u32 outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return false; }
    out[0] = '\0';

    // Display adapter class GUID: {4d36e968-e325-11ce-bfc1-08002be10318}\0000
#ifdef WHIP_BYPASS_MODE
    const wchar_t* subKey =
        L"SYSTEM\\CurrentControlSet\\Control\\Class"
        L"\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000";
    if (!Win32QueryRegSZ(HKEY_LOCAL_MACHINE, subKey, L"MatchingDeviceId", out, outSize)) {
        Win32QueryRegSZ(HKEY_LOCAL_MACHINE, subKey, L"DriverDesc", out, outSize);
    }
    return out[0] != '\0';
#else
    HANDLE hKey = NtOpenRegKey(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class"
        L"\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000");
    if (!hKey) return false;
    // MatchingDeviceId = PCI vendor/device ID (e.g. "pci\ven_10de&dev_2684")
    if (!NtQueryRegSZ(hKey, L"MatchingDeviceId", out, outSize)) {
        // Fallback: driver description (e.g. "NVIDIA GeForce RTX 4090")
        NtQueryRegSZ(hKey, L"DriverDesc", out, outSize);
    }
    GetWrappers().CloseHandle(hKey);
    return out[0] != '\0';
#endif
}

bool WindowsHWIDCollector::collectRamInfo(char* out, u32 outSize) {
    if (outSize < 17) { if (outSize > 0) out[0] = '\0'; return false; }
    out[0] = '\0';

    uint64_t totalRam = 0;

#ifdef WHIP_BYPASS_MODE
    MEMORYSTATUSEX mem = {};
    mem.dwLength = sizeof(mem);
    if (!GlobalMemoryStatusEx(&mem)) return false;
    totalRam = mem.ullTotalPhys;
#else
    // Use NtQuerySystemInformation(SystemBasicInformation = 0) to get total physical pages
    WORD ssn; PVOID addr;
    if (!GetResolver().ResolveByName("NtQuerySystemInformation", ssn, addr)) return false;

    struct { ULONG Reserved; ULONG TimerResolution; ULONG PageSize; ULONG NumberOfPhysicalPages;
             ULONG LowestPhysicalPageNumber; ULONG HighestPhysicalPageNumber;
             ULONG AllocationGranularity; ULONG_PTR MinimumUserModeAddress;
             ULONG_PTR MaximumUserModeAddress; ULONG_PTR ActiveProcessorsAffinityMask;
             CCHAR NumberOfProcessors; } sysInfo = {};

    ULONG retLen = 0;
    NTSTATUS s = SyscallInvoker::Invoke(ssn,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0)), // SystemBasicInformation
        &sysInfo,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(sysInfo))),
        &retLen);
    if (!NT_SUCCESS(s)) return false;

    totalRam = (uint64_t)sysInfo.NumberOfPhysicalPages * (uint64_t)sysInfo.PageSize;
#endif

    // Convert to hex string (16 chars for 64-bit value)
    for (int j = 15; j >= 0; j--) {
        out[15 - j] = s_hex[(totalRam >> (j * 4)) & 0xF];
    }
    out[16] = '\0';
    return true;
}

bool WindowsHWIDCollector::collectTpmId(char* out, u32 outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return false; }
    out[0] = '\0';

#ifdef WHIP_BYPASS_MODE
    const wchar_t* subKey = L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI";
    if (!Win32QueryRegSZ(HKEY_LOCAL_MACHINE, subKey, L"WindowsAIKHash", out, outSize)) {
        Win32QueryRegSZ(HKEY_LOCAL_MACHINE, subKey, L"ManufacturerId", out, outSize);
    }
    return out[0] != '\0';
#else
    HANDLE hKey = NtOpenRegKey(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI");
    if (!hKey) return false;
    if (!NtQueryRegSZ(hKey, L"WindowsAIKHash", out, outSize)) {
        NtQueryRegSZ(hKey, L"ManufacturerId", out, outSize);
    }
    GetWrappers().CloseHandle(hKey);
    return out[0] != '\0';
#endif
}

bool WindowsHWIDCollector::collectBoardSerial(char* out, u32 outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return false; }
    out[0] = '\0';

#ifdef WHIP_BYPASS_MODE
    const wchar_t* subKey = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
    if (!Win32QueryRegSZ(HKEY_LOCAL_MACHINE, subKey, L"BaseBoardSerialNumber", out, outSize)) {
        Win32QueryRegSZ(HKEY_LOCAL_MACHINE, subKey, L"BaseBoardProduct", out, outSize);
    }
    return out[0] != '\0';
#else
    HANDLE hKey = NtOpenRegKey(
        L"\\Registry\\Machine\\HARDWARE\\Description\\System\\BIOS");
    if (!hKey) return false;
    if (!NtQueryRegSZ(hKey, L"BaseBoardSerialNumber", out, outSize)) {
        NtQueryRegSZ(hKey, L"BaseBoardProduct", out, outSize);
    }
    GetWrappers().CloseHandle(hKey);
    return out[0] != '\0';
#endif
}

bool WindowsHWIDCollector::collectMachineGuid(char* out, u32 outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return false; }
    out[0] = '\0';

#ifdef WHIP_BYPASS_MODE
    return Win32QueryRegSZ(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", out, outSize);
#else
    HANDLE hKey = NtOpenRegKey(
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
    if (!hKey) return false;
    bool ok = NtQueryRegSZ(hKey, L"MachineGuid", out, outSize);
    GetWrappers().CloseHandle(hKey);
    return ok;
#endif
}

bool WindowsHWIDCollector::collectBiosSerial(char* out, u32 outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return false; }
    out[0] = '\0';

#ifdef WHIP_BYPASS_MODE
    return Win32QueryRegSZ(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS",
        L"SystemSerialNumber", out, outSize);
#else
    HANDLE hKey = NtOpenRegKey(
        L"\\Registry\\Machine\\HARDWARE\\Description\\System\\BIOS");
    if (!hKey) return false;
    bool ok = NtQueryRegSZ(hKey, L"SystemSerialNumber", out, outSize);
    GetWrappers().CloseHandle(hKey);
    return ok;
#endif
}

bool WindowsHWIDCollector::collect(HWID& out) {
    // Zero-init all fields
    for (unsigned i = 0; i < sizeof(HWID); i++)
        reinterpret_cast<char*>(&out)[i] = 0;

    collectCpuId(out.cpuId, sizeof(out.cpuId));
    collectBoardSerial(out.boardSerial, sizeof(out.boardSerial));
    collectMachineGuid(out.machineGuid, sizeof(out.machineGuid));
    collectBiosSerial(out.biosSerial, sizeof(out.biosSerial));
    collectGpuId(out.gpuId, sizeof(out.gpuId));
    collectRamInfo(out.ramInfo, sizeof(out.ramInfo));
    collectTpmId(out.tpmId, sizeof(out.tpmId));

    if (!out.isValid()) return false;
    return out.computeHash();
}

bool WindowsHWIDCollector::collectGpuName(char* out, u32 outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return false; }
    out[0] = '\0';
#ifdef WHIP_BYPASS_MODE
    const wchar_t* subKey =
        L"SYSTEM\\CurrentControlSet\\Control\\Class"
        L"\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000";
    return Win32QueryRegSZ(HKEY_LOCAL_MACHINE, subKey, L"DriverDesc", out, outSize);
#else
    HANDLE hKey = NtOpenRegKey(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class"
        L"\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000");
    if (!hKey) return false;
    bool ok = NtQueryRegSZ(hKey, L"DriverDesc", out, outSize);
    GetWrappers().CloseHandle(hKey);
    return ok;
#endif
}

bool WindowsHWIDCollector::collectCpuBrand(char* out, u32 outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return false; }
    out[0] = '\0';
#ifdef WHIP_BYPASS_MODE
    return Win32QueryRegSZ(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        L"ProcessorNameString", out, outSize);
#else
    HANDLE hKey = NtOpenRegKey(
        L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0");
    if (!hKey) return false;
    bool ok = NtQueryRegSZ(hKey, L"ProcessorNameString", out, outSize);
    GetWrappers().CloseHandle(hKey);
    return ok;
#endif
}

static bool boardModelIsPlaceholder(const char* s) {
    if (!s || !s[0]) return true;
    const char* ph[] = {
        "System Product Name", "To be filled by O.E.M.",
        "Default string", "Not Applicable", nullptr
    };
    for (int i = 0; ph[i]; i++) {
        const char* a = s, * b = ph[i];
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return true;
    }
    return false;
}

bool WindowsHWIDCollector::collectBoardModel(char* out, u32 outSize) {
    if (outSize < 2) { if (outSize > 0) out[0] = '\0'; return false; }
    out[0] = '\0';
#ifdef WHIP_BYPASS_MODE
    const wchar_t* subKey = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
    // 1. SystemFamily is the human-readable product line (e.g. "Legion T5 26AMR5")
    if (Win32QueryRegSZ(HKEY_LOCAL_MACHINE, subKey, L"SystemFamily", out, outSize)
        && !boardModelIsPlaceholder(out)) return true;
    out[0] = '\0';
    // 2. SystemProductName fallback
    if (Win32QueryRegSZ(HKEY_LOCAL_MACHINE, subKey, L"SystemProductName", out, outSize)
        && !boardModelIsPlaceholder(out)) return true;
    out[0] = '\0';
    // 3. Manufacturer + BaseBoardProduct
    {
        char mfr[128] = {}, prod[128] = {};
        Win32QueryRegSZ(HKEY_LOCAL_MACHINE, subKey, L"BaseBoardManufacturer", mfr, sizeof(mfr));
        Win32QueryRegSZ(HKEY_LOCAL_MACHINE, subKey, L"BaseBoardProduct", prod, sizeof(prod));
        if (prod[0]) {
            if (mfr[0]) snprintf(out, outSize, "%s %s", mfr, prod);
            else { u32 i = 0; while (prod[i] && i < outSize-1) out[i++] = prod[i]; out[i] = '\0'; }
            return true;
        }
    }
    return false;
#else
    HANDLE hKey = NtOpenRegKey(
        L"\\Registry\\Machine\\HARDWARE\\Description\\System\\BIOS");
    if (!hKey) return false;
    // 1. SystemFamily
    if (NtQueryRegSZ(hKey, L"SystemFamily", out, outSize) && !boardModelIsPlaceholder(out)) {
        GetWrappers().CloseHandle(hKey); return true;
    }
    out[0] = '\0';
    // 2. SystemProductName
    if (NtQueryRegSZ(hKey, L"SystemProductName", out, outSize) && !boardModelIsPlaceholder(out)) {
        GetWrappers().CloseHandle(hKey); return true;
    }
    out[0] = '\0';
    // 3. Manufacturer + BaseBoardProduct
    {
        char mfr[128] = {}, prod[128] = {};
        NtQueryRegSZ(hKey, L"BaseBoardManufacturer", mfr, 128);
        NtQueryRegSZ(hKey, L"BaseBoardProduct", prod, 128);
        if (prod[0]) {
            if (mfr[0]) snprintf(out, outSize, "%s %s", mfr, prod);
            else { u32 i = 0; while (prod[i] && i < outSize-1) out[i++] = prod[i]; out[i] = '\0'; }
            GetWrappers().CloseHandle(hKey);
            return true;
        }
    }
    GetWrappers().CloseHandle(hKey);
    return false;
#endif
}

namespace {
    struct ScreenCtx { char* out; u32 sz; u32 pos; };
    static BOOL CALLBACK screenEnumProc(HMONITOR hm, HDC, LPRECT, LPARAM lp) {
        auto* ctx = reinterpret_cast<ScreenCtx*>(lp);
        MONITORINFOEXA mi = {}; mi.cbSize = sizeof(mi);
        if (!GetMonitorInfoA(hm, reinterpret_cast<LPMONITORINFO>(&mi))) return TRUE;
        DEVMODEA dm = {}; dm.dmSize = sizeof(dm);
        if (!EnumDisplaySettingsA(mi.szDevice, ENUM_CURRENT_SETTINGS, &dm)) return TRUE;
        if (!dm.dmPelsWidth || !dm.dmPelsHeight) return TRUE;
        char buf[32];
        int n;
        if (dm.dmDisplayFrequency > 1)
            n = snprintf(buf, sizeof(buf), "%lux%lu@%luHz", dm.dmPelsWidth, dm.dmPelsHeight, dm.dmDisplayFrequency);
        else
            n = snprintf(buf, sizeof(buf), "%lux%lu", dm.dmPelsWidth, dm.dmPelsHeight);
        if (n <= 0) return TRUE;
        if (ctx->pos > 0 && ctx->pos + 2 < ctx->sz) { ctx->out[ctx->pos++] = ','; ctx->out[ctx->pos++] = ' '; }
        u32 copy = (u32)n;
        if (ctx->pos + copy + 1 >= ctx->sz) copy = ctx->sz - ctx->pos - 1;
        for (u32 j = 0; j < copy; j++) ctx->out[ctx->pos++] = buf[j];
        ctx->out[ctx->pos] = '\0';
        return TRUE;
    }
}

bool WindowsHWIDCollector::collectScreenInfo(char* out, u32 outSize) {
    if (outSize < 8) { if (outSize > 0) out[0] = '\0'; return false; }
    out[0] = '\0';
    ScreenCtx ctx = { out, outSize, 0 };
    EnumDisplayMonitors(nullptr, nullptr, screenEnumProc, reinterpret_cast<LPARAM>(&ctx));
    return out[0] != '\0';
}

bool WindowsHWIDCollector::collectStorageInfo(char* out, u32 outSize) {
    if (outSize < 4) { if (outSize > 0) out[0] = '\0'; return false; }
    out[0] = '\0';
    ULARGE_INTEGER total = {}, free2 = {}, avail = {};
    if (!GetDiskFreeSpaceExA("C:\\", &avail, &total, &free2)) return false;
    unsigned long long gb = (unsigned long long)(total.QuadPart / (1024ULL * 1024 * 1024));
    snprintf(out, outSize, "%llu Go", gb);
    return out[0] != '\0';
}

bool WindowsHWIDCollector::collectWithInfo(HWID& out, HWIDDisplayInfo& info) {
    bool ok = collect(out);
    collectGpuName(info.gpuName, sizeof(info.gpuName));
    collectCpuBrand(info.cpuBrand, sizeof(info.cpuBrand));
    // ramHex is the same hex string as out.ramInfo
    u32 i = 0;
    while (out.ramInfo[i] && i < sizeof(info.ramHex) - 1) { info.ramHex[i] = out.ramInfo[i]; i++; }
    info.ramHex[i] = '\0';
    collectBoardModel(info.boardModel, sizeof(info.boardModel));
    collectScreenInfo(info.screenInfo, sizeof(info.screenInfo));
    collectStorageInfo(info.storageInfo, sizeof(info.storageInfo));
    return ok;
}

// ─── Factory ─────────────────────────────────────────────────────────────────

IHWIDCollector* createHWIDCollector() {
    return new WindowsHWIDCollector();
}

// ─── HWID methods ────────────────────────────────────────────────────────────

bool HWID::isValid() const {
    return cpuId[0] != '\0' || boardSerial[0] != '\0'
           || machineGuid[0] != '\0' || biosSerial[0] != '\0'
           || gpuId[0] != '\0' || ramInfo[0] != '\0' || tpmId[0] != '\0';
}

bool HWID::computeHash() {
    // Concatenate all components into a single buffer
    char combined[512] = {};
    DWORD pos = 0;

    const char* parts[] = { cpuId, boardSerial, machineGuid, biosSerial, gpuId, ramInfo, tpmId };
    for (int p = 0; p < 7; p++) {
        const char* s = parts[p];
        while (*s && pos < sizeof(combined) - 1) combined[pos++] = *s++;
    }
    combined[pos] = '\0';

    // SHA-256 via BCrypt
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BYTE hashBytes[32] = {};
    BYTE hashObject[512] = {};
    DWORD cbObjectLen = 0, cbHash = 0, cbResult = 0;

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
    BCryptFinishHash(hHash, hashBytes, cbHash, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Convert to hex
    for (DWORD i = 0; i < 32; i++) {
        hash[i * 2]     = s_hex[(hashBytes[i] >> 4) & 0xF];
        hash[i * 2 + 1] = s_hex[hashBytes[i] & 0xF];
    }
    hash[64] = '\0';
    return true;
}

#pragma optimize("", on)
