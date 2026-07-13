#pragma optimize("", off)
#include "loader/Loader.h"
#include "LoaderInternal.h"
#include <cstdarg>
#include <cstdio>

// Reliable standalone-vs-mapped discriminator based on the host EXE name.
// __ImageBase compare was unreliable when manual-mapped.
static bool isStandaloneLoader() {
    wchar_t exeName[MAX_PATH] = {0};
    DWORD nl = GetModuleFileNameW(nullptr, exeName, MAX_PATH);
    if (nl == 0 || nl >= MAX_PATH) return false;
    const wchar_t* b = exeName;
    for (DWORD i = nl; i > 0; --i) {
        if (exeName[i - 1] == L'\\' || exeName[i - 1] == L'/') { b = exeName + i; break; }
    }
    return _wcsicmp(b, L"WhipLoader.exe") == 0;
}
#include "application/Application.h"
#include "config/Config.h"
#include "config/BuildConfig.h"
#include "security/EmbeddedData.h"
#include "security/HWIDCollector.h"
#include "security/SecureMemory.h"
#include "auth/Credentials.h"
#include "network/WhipNexusClient.h"
#include "ipc/LoaderIpcServer.h"
#include "security/xor.h"

#include <windows.h>
#include <winternl.h>
#include <whipsyscall/WhipSysCall.h>
#include <thread>
#include <chrono>
#include <cstring>

namespace loader_detail {

SyscallResolver& WF_Resolver() {
    static SyscallResolver s_res;
    static bool s_init = s_res.Init();
    (void)s_init;
    return s_res;
}

void WF_Sleep(DWORD ms) {
#ifdef WHIP_BYPASS_MODE
    Sleep(ms);
#else
    WORD ssn; PVOID addr;
    if (!WF_Resolver().ResolveByName("NtDelayExecution", ssn, addr)) {
        Sleep(ms); // fallback so callers don't spin
        return;
    }
    LARGE_INTEGER delay;
    delay.QuadPart = -(LONGLONG)ms * 10000LL;
    SyscallInvoker::Invoke(
        ssn,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(FALSE)),
        &delay
    );
#endif
}

void WF_GetComputerName(char* dst, u32 dstSize) {
    authStrCopy(dst, "Unknown", dstSize);

#ifdef WHIP_BYPASS_MODE
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) return;
    wchar_t wname[256] = {};
    DWORD cb = sizeof(wname), type = 0;
    LSTATUS s = RegQueryValueExW(hKey, L"ComputerName", nullptr, &type,
                                 reinterpret_cast<LPBYTE>(wname), &cb);
    RegCloseKey(hKey);
    if (s != ERROR_SUCCESS || type != REG_SZ) return;
    DWORD wlen = cb / sizeof(wchar_t);
    if (wlen > 0 && wname[wlen - 1] == L'\0') wlen--;
    if (wlen == 0) return;
    int n = WideCharToMultiByte(CP_UTF8, 0, wname, (int)wlen,
                                nullptr, 0, nullptr, nullptr);
    if (n <= 0 || static_cast<u32>(n) >= dstSize) return;
    WideCharToMultiByte(CP_UTF8, 0, wname, (int)wlen, dst, n, nullptr, nullptr);
    dst[n] = '\0';
    return;
#else
    WORD ssn_ok; PVOID addr;
    if (!WF_Resolver().ResolveByName("NtOpenKey", ssn_ok, addr)) return;

    const wchar_t* keyPath =
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName";
    SIZE_T kl = 0; while (keyPath[kl]) kl++;
    UNICODE_STRING ks;
    ks.Length        = static_cast<USHORT>(kl * sizeof(wchar_t));
    ks.MaximumLength = ks.Length + static_cast<USHORT>(sizeof(wchar_t));
    ks.Buffer        = const_cast<PWSTR>(keyPath);
    OBJECT_ATTRIBUTES oa = {};
    oa.Length = sizeof(oa); oa.ObjectName = &ks; oa.Attributes = 0x40;

    HANDLE hKey = nullptr;
    NTSTATUS s = SyscallInvoker::Invoke(
        ssn_ok,
        &hKey,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(0x20019)),
        &oa
    );
    if (!NT_SUCCESS(s) || !hKey) return;

    WORD ssn_qv;
    if (!WF_Resolver().ResolveByName("NtQueryValueKey", ssn_qv, addr)) {
        WORD ssn_c; if (WF_Resolver().ResolveByName("NtClose", ssn_c, addr))
            SyscallInvoker::Invoke(ssn_c, hKey);
        return;
    }

    const wchar_t* valName = L"ComputerName";
    SIZE_T vl = 0; while (valName[vl]) vl++;
    UNICODE_STRING vs;
    vs.Length        = static_cast<USHORT>(vl * sizeof(wchar_t));
    vs.MaximumLength = vs.Length + static_cast<USHORT>(sizeof(wchar_t));
    vs.Buffer        = const_cast<PWSTR>(valName);

    uint8_t buf[512] = {};
    ULONG ret = 0;
    NTSTATUS s2 = SyscallInvoker::Invoke(
        ssn_qv,
        hKey, &vs,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(2)),
        buf,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(sizeof(buf))),
        &ret
    );

    WORD ssn_c; if (WF_Resolver().ResolveByName("NtClose", ssn_c, addr))
        SyscallInvoker::Invoke(ssn_c, hKey);

    if (!NT_SUCCESS(s2)) return;
    ULONG type    = *reinterpret_cast<ULONG*>(buf + 4);
    ULONG dataLen = *reinterpret_cast<ULONG*>(buf + 8);
    if (type != 1 || dataLen < 2) return;
    auto* wstr = reinterpret_cast<const wchar_t*>(buf + 12);
    ULONG wlen  = dataLen / sizeof(wchar_t);
    if (wlen > 0 && wstr[wlen - 1] == L'\0') wlen--;
    if (wlen == 0) return;
    int n = WideCharToMultiByte(CP_UTF8, 0, wstr, (int)wlen, nullptr, 0, nullptr, nullptr);
    if (n <= 0 || static_cast<u32>(n) >= dstSize) return;
    WideCharToMultiByte(CP_UTF8, 0, wstr, (int)wlen, dst, n, nullptr, nullptr);
    dst[n] = '\0';
#endif // WHIP_BYPASS_MODE
}

void WF_GetOsVersion(char* dst, u32 dstSize) {
    const auto* ksd = reinterpret_cast<const uint8_t*>(0x7FFE0000ULL);
    ULONG major = *reinterpret_cast<const ULONG*>(ksd + 0x26C); // NtMajorVersion
    ULONG minor = *reinterpret_cast<const ULONG*>(ksd + 0x270); // NtMinorVersion
    ULONG build = *reinterpret_cast<const ULONG*>(ksd + 0x260); // NtBuildNumber

    char tmp[64];
    int pos = 0;
    auto writeStr = [&](const char* s) { while (*s && pos < 63) tmp[pos++] = *s++; };
    auto writeUL = [&](ULONG v) {
        char digits[12]; int d = 0;
        if (v == 0) { digits[d++] = '0'; }
        else { while (v) { digits[d++] = '0' + (char)(v % 10); v /= 10; } }
        for (int i = d - 1; i >= 0 && pos < 63; i--) tmp[pos++] = digits[i];
    };
    writeStr("Windows ");
    writeUL(major); tmp[pos++] = '.';
    writeUL(minor); tmp[pos++] = '.';
    writeUL(build);
    tmp[pos] = '\0';

    authStrCopy(dst, tmp, dstSize);
}

void WF_GetExecutablePath(char* dst, u32 dstSize) {
    authStrCopy(dst, "Unknown", dstSize);

    wchar_t wpath[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, wpath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return;

    int n = WideCharToMultiByte(CP_UTF8, 0, wpath, len, nullptr, 0, nullptr, nullptr);
    if (n <= 0 || static_cast<u32>(n) >= dstSize) return;

    WideCharToMultiByte(CP_UTF8, 0, wpath, len, dst, n, nullptr, nullptr);
    dst[n] = '\0';
}

} // namespace loader_detail

Loader::Loader()
    : ctx{}, dependencies{}, cbStepChanged(nullptr), cbError(nullptr), cbComplete(nullptr),
      initialized(false), running(false), downloadId{}, machineInfo{}, hwid{},
      targetProcess{}, moduleData{}, nexusClient(), ipcServer(), ipcPort(0),
      heartbeatThread(), heartbeatRunning(false), heartbeatCV{}, heartbeatMutex{},
      processWatchThread(), processWatchRunning(false), injector(), injectionResult{}
{
}

Loader::~Loader() {
    shutdown();
}

void Loader::setDependencies(const LoaderDependencies& deps) {
    this->dependencies = deps;
}

VoidResult Loader::initialize() {
    ctx = LoaderContext{};

    nexusClient = std::make_unique<WhipNexusClient>();
    auto initResult = nexusClient->initialize();
    if (!initResult) {
        return initResult;
    }

    initialized = true;
    return VoidResult::ok();
}

void Loader::shutdown() {
    stop();

    processWatchRunning = false;
    if (processWatchThread.joinable()) {
        processWatchThread.join();
    }

    heartbeatRunning = false;
    if (heartbeatThread.joinable()) {
        heartbeatThread.join();
    }

    // ipcServer->stop() can hang or deadlock because the underlying
    // WhipNexusServer::stop() uses TerminateThread() on its accept thread
    // and every client thread. That can leave the clientMutex orphaned and
    // a follow-on EnterCriticalSection blocks forever. We run it on a side
    // thread with a 2-second timeout — that gives the server a chance to
    // send the FIN cleanly while guaranteeing forward progress.
    if (ipcServer) {
        LoaderIpcServer* rawSrv = ipcServer.get();
        HANDLE doneEvt = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        struct StopCtx { LoaderIpcServer* srv; HANDLE evt; };
        StopCtx* sctx = new StopCtx{ rawSrv, doneEvt };
        HANDLE stopThread = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
            StopCtx* c = static_cast<StopCtx*>(p);
            try { c->srv->stop(); } catch (...) {}
            SetEvent(c->evt);
            delete c;
            return 0;
        }, sctx, 0, nullptr);

        if (stopThread) {
            DWORD wait = WaitForSingleObject(doneEvt, 2000);
            if (wait == WAIT_OBJECT_0) {
                ipcServer.reset();
            } else {
                // Stop hung — leak so destructor doesn't deadlock. Kernel reaps on TerminateProcess.
                (void)ipcServer.release();
            }
            CloseHandle(stopThread);
        } else {
            // CreateThread failed — fall back to inline stop (risk of hang).
            try { rawSrv->stop(); } catch (...) {}
            ipcServer.reset();
            delete sctx;
        }
        if (doneEvt) CloseHandle(doneEvt);
    }

    if (nexusClient) {
        WhipNexusClient* rawNexus = nexusClient.get();
        HANDLE doneEvt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        struct DiscCtx { WhipNexusClient* nex; HANDLE evt; };
        DiscCtx* dctx = new DiscCtx{ rawNexus, doneEvt };
        HANDLE discThread = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
            DiscCtx* c = static_cast<DiscCtx*>(p);
            try { c->nex->disconnect(); } catch (...) {}
            SetEvent(c->evt);
            delete c;
            return 0;
        }, dctx, 0, nullptr);

        if (discThread) {
            DWORD wait = WaitForSingleObject(doneEvt, 4000);
            if (wait == WAIT_OBJECT_0) {
                nexusClient.reset();
            } else {
                (void)nexusClient.release();
            }
            CloseHandle(discThread);
        } else {
            try { rawNexus->disconnect(); } catch (...) {}
            nexusClient.reset();
            delete dctx;
        }
        if (doneEvt) CloseHandle(doneEvt);
    }

    initialized = false;
}

bool Loader::isInitialized() const noexcept {
    return initialized;
}

VoidResult Loader::start() {
    if (running) {
        return VoidResult::err(ErrorCode::InvalidArgument, "Workflow already running");
    }

    running = true;
    transitionTo(LoaderStep::WaitingForProcess, "Waiting for Minecraft...");
    executeCurrentStep();
    return VoidResult::ok();
}

void Loader::stop() {
    running = false;
}

void Loader::retry() {
    if (!ctx.canRetry) { return; }

    ctx.lastError.reset();
    executeCurrentStep();
}

LoaderStep Loader::currentStep() const noexcept {
    return ctx.currentStep;
}

const LoaderContext& Loader::context() const noexcept {
    return ctx;
}

bool Loader::isRunning() const noexcept {
    return running;
}

void Loader::setOnStepChanged(OnLoaderStepChanged callback) {
    cbStepChanged = std::move(callback);
}

void Loader::setOnError(OnLoaderError callback) {
    cbError = std::move(callback);
}

void Loader::setOnComplete(OnLoaderComplete callback) {
    cbComplete = std::move(callback);
}

void Loader::selectProduct(int index) {
    if (index >= 0 && index < static_cast<int>(ctx.availableProducts.size())) {
        ctx.selectedProductIndex = index;
        if (ctx.currentStep == LoaderStep::SelectingProduct) {
            executeCurrentStep();
        }
    }
}


void Loader::transitionTo(LoaderStep step, const std::string& message, int percent) {
    ctx.previousStep = ctx.currentStep;
    ctx.currentStep = step;
    ctx.statusMessage = message;
    ctx.canRetry = false;

    // Set progress percentage (if specified, otherwise calculate from step)
    if (percent >= 0) {
        ctx.progressPercent = percent;
    } else {
        // Auto-calculate based on workflow step
        switch (step) {
            case LoaderStep::Idle:           ctx.progressPercent = 0; break;
            case LoaderStep::WaitingForProcess: ctx.progressPercent = 5; break;
            case LoaderStep::Connecting:     ctx.progressPercent = 10; break;
            case LoaderStep::Authenticating: ctx.progressPercent = 15; break;
            case LoaderStep::FetchingLicenses: ctx.progressPercent = 20; break;
            case LoaderStep::SelectingProduct: ctx.progressPercent = 25; break;
            case LoaderStep::ValidatingLicense: ctx.progressPercent = 30; break;
            case LoaderStep::DownloadingModule: ctx.progressPercent = 35; break;
            case LoaderStep::Injecting:      ctx.progressPercent = 40; break;
            case LoaderStep::Running:        ctx.progressPercent = 40; break;
            default:                           ctx.progressPercent = 0; break;
        }
    }

    if (cbStepChanged) {
        cbStepChanged(ctx);
    }
}

void Loader::handleError(const Error& error, bool canRetry) {
    Error displayed = error;
    if (displayed.message == "Error #23")
        displayed.message = "Whip already running";
    ctx.lastError = displayed;
    ctx.canRetry = canRetry;
    transitionTo(LoaderStep::Error, displayed.message);

    if (!canRetry) {
        running = false;
    }

    if (cbError) {
        cbError(displayed);
    }
}

static const char* stepName(LoaderStep s) {
    switch (s) {
        case LoaderStep::Idle:               return "Idle";
        case LoaderStep::WaitingForProcess:  return "WaitingForProcess";
        case LoaderStep::Connecting:         return "Connecting";
        case LoaderStep::Authenticating:     return "Authenticating";
        case LoaderStep::FetchingLicenses:   return "FetchingLicenses";
        case LoaderStep::SelectingProduct:   return "SelectingProduct";
        case LoaderStep::ValidatingLicense:  return "ValidatingLicense";
        case LoaderStep::DownloadingModule:  return "DownloadingModule";
        case LoaderStep::Injecting:          return "Injecting";
        case LoaderStep::Running:            return "Running";
        case LoaderStep::Error:              return "Error";
        default:                             return "Unknown";
    }
}

void Loader::executeCurrentStep() {
    while (running) {
        LoaderStep before = ctx.currentStep;

        switch (ctx.currentStep) {
            case LoaderStep::WaitingForProcess:  stepWaitForProcess();  break;
            case LoaderStep::Connecting:         stepConnect();         break;
            case LoaderStep::Authenticating:     stepAuthenticate();    break;
            case LoaderStep::FetchingLicenses:   stepFetchLicenses();   break;
            case LoaderStep::SelectingProduct:   stepSelectProduct();   break;
            case LoaderStep::ValidatingLicense:  stepValidateLicense(); break;
            case LoaderStep::DownloadingModule:  stepDownloadModule();  break;
            case LoaderStep::Injecting:          stepInject();          break;
            default: return;
        }

        LoaderStep after = ctx.currentStep;
        if (after == before ||
            after == LoaderStep::Running ||
            after == LoaderStep::Error   ||
            after == LoaderStep::Idle) {
            return;
        }
    }
}
#pragma optimize("", on)
