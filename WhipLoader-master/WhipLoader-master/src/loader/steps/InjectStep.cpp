#pragma optimize("", off)
#include "loader/Loader.h"
#include "../LoaderInternal.h"
#include "application/Application.h"
#include "config/BuildConfig.h"
#include "network/WhipNexusClient.h"
#include "ipc/LoaderIpcServer.h"
#include "ui/IConsoleUI.h"
#include "injection/ManualMapInjector.h"
#include "security/EmbeddedData.h"
#include "security/Sentinel.h"
#include "security/ReverseDetector.h"
#include "security/xor.h"

#include <Windows.h>
#include <whipsyscall/WhipSysCall.h>
#include <thread>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <string>

namespace {

struct ConfigThreadContext {
    LoaderIpcServer* ipcServer;
    byte token[32];
    byte attestationKey[32];
    char hwid[128];
    u64 authTag;
    volatile LONG completed;
    HANDLE threadHandle;
};

DWORD WINAPI ConfigThreadProc(LPVOID param) {
    auto* ctx = static_cast<ConfigThreadContext*>(param);

    (void)ctx->ipcServer->sendConfig(
        ctx->token,
        ctx->attestationKey,
        XOR("51.178.31.94"),
        BuildConfig::serverPort,
        ctx->hwid,
        ctx->authTag
    );

    InterlockedExchange(&ctx->completed, 1);
    return 0;
}

} // namespace

void Loader::stepInject() {
#ifndef WHIP_BYPASS_MODE
    ReverseDetector::checkAndKill(nexusClient.get(), "InjectStep", targetProcess.processId);
#endif

    using loader_detail::WF_Resolver;
    using loader_detail::WF_Sleep;

#ifndef WHIP_BYPASS_MODE
    Sentinel::recheck();
    Sentinel::verify();
#endif

    if (moduleData.empty()) {
        handleError(Error(ErrorCode::InvalidArgument, "No module data in memory"), false);
        return;
    }

    if (ipcServer && ipcPort > 0) {
        char portStr[8];
        u32 port = ipcPort;
        char digits[6]; int d = 0;
        if (port == 0) { digits[d++] = '0'; }
        else { while (port) { digits[d++] = '0' + (char)(port % 10); port /= 10; } }
        for (int i = 0; i < d; i++) portStr[i] = digits[d - 1 - i];
        portStr[d] = '\0';
        SetEnvironmentVariableA(XOR("WHIP_IPC_PORT"), portStr);
    }

    injector = createInjector();
    if (!injector) {
        handleError(Error(ErrorCode::Unknown, "Failed to create injector"), false);
        return;
    }

    ConfigThreadContext configCtx = {};
    if (ipcServer && ipcServer->isRunning()) {
        const Byte* tempToken = nexusClient->getTemporaryClientToken();
        if (tempToken) {
            configCtx.ipcServer = ipcServer.get();
            memcpy(configCtx.token, tempToken, 32);

            // Per-session attestation token issued by the server in AUTH_RESPONSE.
            // Forwarded to the injected client so it can present it in CLIENT_AUTH
            // — proves the loader→client chain (single-use, server enforces).
            const Byte* attestToken = nexusClient->getClientAttestationToken();
            if (attestToken) {
                memcpy(configCtx.attestationKey, attestToken, 32);
            }

            // Phase 1+2 auth_tag for LOADER_CONFIG. Buffer = temporaryClientToken
            // (32 bytes). The client forwards this tag to the server in
            // CLIENT_AUTH where it is recomputed against download.auth_salt+algoSeed.
            Byte authSalt[16] = {};
            Byte algoSeed[32] = {};
            Byte codeFingerprint[32] = {};
            if (dependencies.embeddedDataReader) {
                (void)dependencies.embeddedDataReader->readAuthSalt(authSalt);
                (void)dependencies.embeddedDataReader->readAlgoSeed(algoSeed);
                (void)dependencies.embeddedDataReader->readCodeFingerprint(codeFingerprint);
            }
            configCtx.authTag = Sentinel::deriveAuthTag(configCtx.token, 32, authSalt, algoSeed, codeFingerprint);

            authStrCopy(configCtx.hwid, machineInfo.hwid, sizeof(configCtx.hwid));
            configCtx.completed = 0;

#ifdef WHIP_BYPASS_MODE
            configCtx.threadHandle = CreateThread(
                nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(ConfigThreadProc),
                &configCtx, 0, nullptr);
            Sleep(100);
#else
            WORD ssn; PVOID addr;
            if (WF_Resolver().ResolveByName("NtCreateThreadEx", ssn, addr)) {
                SyscallInvoker::Invoke(
                    ssn,
                    &configCtx.threadHandle,
                    (PVOID)(ULONG_PTR)THREAD_ALL_ACCESS,
                    nullptr,
                    GetCurrentProcess(),
                    (PVOID)ConfigThreadProc,
                    &configCtx,
                    (PVOID)(ULONG_PTR)0,
                    (PVOID)(ULONG_PTR)0,
                    (PVOID)(ULONG_PTR)0,
                    (PVOID)(ULONG_PTR)0,
                    nullptr
                );
                WF_Sleep(100);
            }
#endif
        }
    }

    auto result = injector->inject(targetProcess, moduleData);

    moduleData.clear();

    if (!result.isOk()) {
        if (configCtx.threadHandle) {
#ifdef WHIP_BYPASS_MODE
            WaitForSingleObject(configCtx.threadHandle, 5000);
            CloseHandle(configCtx.threadHandle);
#else
            WORD ssn; PVOID addr;
            if (WF_Resolver().ResolveByName("NtWaitForSingleObject", ssn, addr)) {
                LARGE_INTEGER timeout;
                timeout.QuadPart = -50000000LL;
                SyscallInvoker::Invoke(ssn, configCtx.threadHandle, (PVOID)(ULONG_PTR)FALSE, &timeout);
            }
            if (WF_Resolver().ResolveByName("NtClose", ssn, addr)) {
                SyscallInvoker::Invoke(ssn, configCtx.threadHandle);
            }
#endif
        }
        handleError(Error(result.error().code, "Injection failed: " + result.error().message), true);
        return;
    }

    injectionResult = result.value();

    if (configCtx.threadHandle) {
#ifdef WHIP_BYPASS_MODE
        WaitForSingleObject(configCtx.threadHandle, 20000);
        CloseHandle(configCtx.threadHandle);
#else
        WORD ssn; PVOID addr;
        if (WF_Resolver().ResolveByName("NtWaitForSingleObject", ssn, addr)) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -200000000LL;
            SyscallInvoker::Invoke(ssn, configCtx.threadHandle, (PVOID)(ULONG_PTR)FALSE, &timeout);
        }
        if (WF_Resolver().ResolveByName("NtClose", ssn, addr)) {
            SyscallInvoker::Invoke(ssn, configCtx.threadHandle);
        }
#endif
    }

    if (dependencies.ui) {
        dependencies.ui->showProgress("Injected into Minecraft", 40);
    }

    transitionTo(LoaderStep::Running, "Running", 40);

    // Start heartbeat first so we have its native handle for ReverseDetector.
    heartbeatRunning = true;
    heartbeatThread = std::thread([this]() {
        // Manually-mapped PE: any C++ exception escaping this lambda
        // reaches std::thread's wrapper, which calls std::terminate() →
        // abort() → __fastfail(7) → STATUS_STACK_BUFFER_OVERRUN
        // (0xC0000409). Catch everything; heartbeat failure is non-fatal.
        try {
            while (heartbeatRunning) {
                for (int i = 0; i < 300 && heartbeatRunning; ++i) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                if (!heartbeatRunning) break;

                if (nexusClient && nexusClient->isConnected()) {
                    try {
                        (void)nexusClient->sendHeartbeat(machineInfo.pcName, machineInfo.executablePath);
                    } catch (...) {}
                }
            }
        } catch (...) {}
    });

    // Start RE-tool background monitor. Pass the heartbeat thread's native
    // handle so ReverseDetector can TerminateThread it before sending —
    // the heartbeat blocks on receiveDecryptedPacket and holds the socket lock.
#ifndef WHIP_BYPASS_MODE
    ReverseDetector::start(nexusClient.get(),
        static_cast<HANDLE>(heartbeatThread.native_handle()),
        machineInfo.pcName, machineInfo.executablePath,
        targetProcess.processId);
#endif

    // Start process watch thread to detect when Minecraft closes
    processWatchRunning = true;
    DWORD watchedPid = injectionResult.processId;
    auto uiPtr = dependencies.ui;
    processWatchThread = std::thread([this, watchedPid, uiPtr]() {
        // Same exception-barrier reasoning as the heartbeat thread above:
        // any escape would __fastfail. UI calls go through std::string and
        // std::cout — both are throw-prone.
        try {
            HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, watchedPid);
            if (!hProcess) {
                processWatchRunning = false;
                return;
            }

            while (processWatchRunning) {
                DWORD waitResult = WaitForSingleObject(hProcess, 1000);
                if (waitResult == WAIT_OBJECT_0) {
                    CloseHandle(hProcess);

                    if (uiPtr) {
                        uiPtr->showWindow();
                        uiPtr->showProgress("Game closed", 0);
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(3));

                    if (uiPtr) uiPtr->hideWindow();
                    TerminateProcess(GetCurrentProcess(), 0);
                    return;
                }
            }

            CloseHandle(hProcess);
        } catch (...) {}
    });

    if (cbComplete) {
        cbComplete();
    }
}
#pragma optimize("", on)
