#include "injection/ProcessFinder.h"

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>
#include <vector>

// NtQueryInformationProcess is exported from ntdll but not auto-imported
// by the default link libraries on every toolchain. Force the link so the
// declared prototype in <winternl.h> resolves at link time.
#pragma comment(lib, "ntdll.lib")

// ─── Utilities ────────────────────────────────────────────────────────────────

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static std::string wideToUtf8(const wchar_t* wide, size_t len) {
    if (!wide || len == 0) return "";
    int needed = WideCharToMultiByte(CP_UTF8, 0, wide, (int)len, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return "";
    std::string result(needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, (int)len, result.data(), needed, nullptr, nullptr);
    return result;
}

// ─── Process enumeration via Toolhelp32 (pure Win32) ──────────────────────────
//
// Replaces the previous SyscallResolver + NtQuerySystemInformation path,
// which failed silently when the indirect-syscall resolver could not locate
// the ntdll!Nt* stubs (e.g. inside Lunar Client, where ntdll is hooked or
// the syscall stubs are rewritten).

struct EnumeratedProc {
    uint32_t    pid;
    std::string name;
};

static std::vector<EnumeratedProc> EnumProcesses() {
    std::vector<EnumeratedProc> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            EnumeratedProc e;
            e.pid = pe.th32ProcessID;
            int len = WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                          nullptr, 0, nullptr, nullptr);
            if (len > 1) {
                e.name.resize(len - 1);
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                    e.name.data(), len, nullptr, nullptr);
            }
            out.push_back(std::move(e));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

// Read CommandLine via the PEB. NtQueryInformationProcess is the ntdll
// export — NOT an indirect syscall — so this still works when the syscall
// resolver is broken.
static std::string readProcessCommandLine(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi{};
    NTSTATUS s = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                           &pbi, sizeof(pbi), nullptr);
    if (!NT_SUCCESS(s) || !pbi.PebBaseAddress) return "";

    PEB peb{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &read))
        return "";

    RTL_USER_PROCESS_PARAMETERS params{};
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), &read))
        return "";

    USHORT cmdLen = params.CommandLine.Length;
    if (cmdLen == 0 || cmdLen > 32767 * 2) return "";

    std::vector<wchar_t> cmdBuf(cmdLen / sizeof(wchar_t));
    if (!ReadProcessMemory(hProcess, params.CommandLine.Buffer,
                           cmdBuf.data(), cmdLen, &read))
        return "";

    return wideToUtf8(cmdBuf.data(), cmdBuf.size());
}

// ─── Impl ─────────────────────────────────────────────────────────────────────

struct ProcessFinder::Impl {
    OnProcessFound onFound;
    OnProcessLost  onLost;
    bool           monitoring = false;
};

ProcessFinder::ProcessFinder() : impl_(std::make_unique<Impl>()) {}
ProcessFinder::~ProcessFinder() { stopMonitoring(); }

Result<ProcessInfo> ProcessFinder::findByName(const std::string& processName) {
    auto result = findAllByName(processName);
    if (!result.isOk()) return Result<ProcessInfo>::err(result.error());
    auto& list = result.value();
    if (list.empty()) return Result<ProcessInfo>::err(ErrorCode::NotFound, "Process not found: " + processName);
    return Result<ProcessInfo>::ok(std::move(list[0]));
}

Result<ProcessInfo> ProcessFinder::findByPid(uint32_t pid) {
    auto procs = EnumProcesses();
    if (procs.empty())
        return Result<ProcessInfo>::err(ErrorCode::Unknown, "CreateToolhelp32Snapshot failed");

    for (const auto& p : procs) {
        if (p.pid == pid) {
            ProcessInfo info;
            info.processId = p.pid;
            info.name      = p.name;
            info.is64Bit   = true;
            return Result<ProcessInfo>::ok(std::move(info));
        }
    }
    return Result<ProcessInfo>::err(ErrorCode::NotFound, "PID not found");
}

Result<std::vector<ProcessInfo>> ProcessFinder::findAllByName(const std::string& processName) {
    auto procs = EnumProcesses();
    if (procs.empty())
        return Result<std::vector<ProcessInfo>>::err(ErrorCode::Unknown, "CreateToolhelp32Snapshot failed");

    std::vector<ProcessInfo> results;
    std::string targetLower = toLower(processName);
    // strip .exe suffix from target if present, to allow matching both "foo" and "foo.exe"
    auto stripExe = [](std::string s) -> std::string {
        if (s.size() > 4 && s.substr(s.size() - 4) == ".exe")
            s.resize(s.size() - 4);
        return s;
    };
    std::string targetStem = stripExe(targetLower);

    for (const auto& p : procs) {
        std::string nameLower = toLower(p.name);
        if (nameLower == targetLower || stripExe(nameLower) == targetStem) {
            ProcessInfo info;
            info.processId = p.pid;
            info.name      = p.name;
            info.is64Bit   = true;
            results.push_back(std::move(info));
        }
    }
    return Result<std::vector<ProcessInfo>>::ok(std::move(results));
}

Result<std::vector<ProcessInfo>> ProcessFinder::findJavaByKeyword(const std::string& keyword) {
    auto procs = EnumProcesses();
    if (procs.empty())
        return Result<std::vector<ProcessInfo>>::err(ErrorCode::Unknown, "CreateToolhelp32Snapshot failed");

    std::vector<ProcessInfo> javaw_results;
    std::vector<ProcessInfo> java_results;
    std::string keywordLower = toLower(keyword);

    for (const auto& p : procs) {
        std::string nameLower = toLower(p.name);
        bool isJavaw = nameLower == "javaw.exe";
        bool isJava  = nameLower == "java.exe";
        if (!isJavaw && !isJava) continue;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                                   FALSE, p.pid);
        if (!hProc) continue;

        std::string cmdLine = readProcessCommandLine(hProc);
        CloseHandle(hProc);

        if (!cmdLine.empty() &&
            toLower(cmdLine).find(keywordLower) != std::string::npos) {
            ProcessInfo info;
            info.processId   = p.pid;
            info.name        = p.name;
            info.commandLine = std::move(cmdLine);
            info.is64Bit     = true;
            (isJavaw ? javaw_results : java_results).push_back(std::move(info));
        }
    }

    // Prefer javaw.exe; fall back to java.exe only if none found.
    if (!javaw_results.empty())
        return Result<std::vector<ProcessInfo>>::ok(std::move(javaw_results));
    return Result<std::vector<ProcessInfo>>::ok(std::move(java_results));
}

Result<ProcessInfo> ProcessFinder::waitForProcess(const std::string& processName, Duration timeout) {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < timeout) {
        auto result = findByName(processName);
        if (result.isOk()) return result;
        Sleep(1250);
    }
    return Result<ProcessInfo>::err(ErrorCode::NotFound, "Timeout waiting for: " + processName);
}

void ProcessFinder::startMonitoring(const std::string&, Duration) {
    impl_->monitoring = true;
}
void ProcessFinder::stopMonitoring() {
    impl_->monitoring = false;
}
bool ProcessFinder::isMonitoring() const noexcept {
    return impl_->monitoring;
}
void ProcessFinder::setOnProcessFound(OnProcessFound callback) {
    impl_->onFound = std::move(callback);
}
void ProcessFinder::setOnProcessLost(OnProcessLost callback) {
    impl_->onLost = std::move(callback);
}

bool ProcessFinder::isProcessRunning(uint32_t pid) const {
    HANDLE hProc = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!hProc) return false;
    DWORD w = WaitForSingleObject(hProc, 0);
    CloseHandle(hProc);
    return w == WAIT_TIMEOUT; // signaled = exited; timeout = still alive
}

bool ProcessFinder::isProcessRunning(const std::string& name) const {
    auto procs = EnumProcesses();
    if (procs.empty()) return false;

    std::string nameLower = toLower(name);
    for (const auto& p : procs) {
        if (toLower(p.name) == nameLower) return true;
    }
    return false;
}

std::unique_ptr<ProcessFinder> createProcessFinder() {
    return std::make_unique<ProcessFinder>();
}
