#include "auth/ipc/LoaderIpcClient.h"
#include "auth/protocol/PacketOpcodes.h"
#include <whipnexus/WhipNexus.h>
#include <whipnexus/BinaryReader.h>
#include <whipnexus/BinaryWriter.h>
#include <whipsyscall/WhipSysCall.h>
#include <ctime>
#include "util/Debug.h"

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

static SyscallResolver& GetSyscallResolver() {
    static SyscallResolver s_resolver;
    static bool s_init = s_resolver.Init();
    (void)s_init;
    return s_resolver;
}

struct ConfigResponseContext {
    HANDLE completedEvent = nullptr;
    bool received = false;
    LoaderConfig config;
};

static void onLoaderConfig(u16 opcode, const byte* data, u32 length, void* ctx) {
#ifdef VMP
    VMProtectBeginUltra("onLoaderConfig");
#endif
    auto* context = static_cast<ConfigResponseContext*>(ctx);

    BinaryReader reader(data, length);

    byte tempToken[32];
    reader.readFixedBytes(tempToken, 32);
    for (u32 i = 0; i < 32; ++i) {
        context->config.temporaryClientToken.data[i] = tempToken[i];
    }

    volatile byte* p = tempToken;
    for (u32 i = 0; i < 32; ++i) {
        p[i] = 0;
    }

    byte attestKey[32];
    reader.readFixedBytes(attestKey, 32);
    for (u32 i = 0; i < 32; ++i) {
        context->config.clientAttestationKey.data[i] = attestKey[i];
    }

    volatile byte* pk = attestKey;
    for (u32 i = 0; i < 32; ++i) {
        pk[i] = 0;
    }

    char hostBuf[256];
    reader.readString(hostBuf, sizeof(hostBuf));
    context->config.serverHost = hostBuf;

    context->config.serverPort = reader.readShort();

    char hwidBuf[256];
    reader.readString(hwidBuf, sizeof(hwidBuf));
    context->config.hwid = hwidBuf;

    context->config.timestamp = reader.readLong();
    context->config.loaderAuthTag = static_cast<uint64_t>(reader.readLong());

    context->received = true;

    WORD ssn; PVOID addr;
    if (GetSyscallResolver().ResolveByName("NtSetEvent", ssn, addr)) {
        SyscallInvoker::Invoke(ssn, context->completedEvent, nullptr);
    }
#ifdef VMP
    VMProtectEnd();
#endif
}

struct LoaderIpcClient::Impl {
    WhipNexus nexus;
    bool connected = false;
    ConfigResponseContext configCtx;

    volatile LONG ipcThreadRunning = 0;
    HANDLE ipcThread = nullptr;
    HANDLE stopEvent = nullptr;

    static DWORD WINAPI ipcThreadProc(LPVOID param);
};

LoaderIpcClient::LoaderIpcClient() : impl_(std::make_unique<Impl>()) {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_ctor");
#endif
#ifdef VMP
    VMProtectEnd();
#endif
}

LoaderIpcClient::~LoaderIpcClient() {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_dtor");
#endif
    stopIpcThread();
    disconnect();
    if (impl_->configCtx.completedEvent) {

        WORD ssn; PVOID addr;
        if (GetSyscallResolver().ResolveByName("NtClose", ssn, addr)) {
            SyscallInvoker::Invoke(ssn, impl_->configCtx.completedEvent);
        }
    }
    if (impl_->stopEvent) {
        WORD ssn; PVOID addr;
        if (GetSyscallResolver().ResolveByName("NtClose", ssn, addr)) {
            SyscallInvoker::Invoke(ssn, impl_->stopEvent);
        }
        impl_->stopEvent = nullptr;
    }
#ifdef VMP
    VMProtectEnd();
#endif
}

VoidResult LoaderIpcClient::initialize() {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_initialize");
#endif
    if (!impl_->nexus.init()) {
        return VoidResult::err(ErrorCode::NetworkError, "WhipNexus init failed");
    }

    impl_->nexus.setPlainMode(true);

    impl_->nexus.setCertificatePinning(false, nullptr);

    WORD ssn; PVOID addr;
    if (!GetSyscallResolver().ResolveByName("NtCreateEvent", ssn, addr)) {
        return VoidResult::err(ErrorCode::Unknown, "Failed to resolve NtCreateEvent");
    }

    NTSTATUS status = SyscallInvoker::Invoke(
        ssn,
        &impl_->configCtx.completedEvent,
        (PVOID)(ULONG_PTR)EVENT_ALL_ACCESS,
        nullptr,
        (PVOID)(ULONG_PTR)1,
        (PVOID)(ULONG_PTR)FALSE
    );

    if (!NT_SUCCESS(status)) {
        return VoidResult::err(ErrorCode::Unknown, "NtCreateEvent failed");
    }

    status = SyscallInvoker::Invoke(
        ssn,
        &impl_->stopEvent,
        (PVOID)(ULONG_PTR)EVENT_ALL_ACCESS,
        nullptr,
        (PVOID)(ULONG_PTR)1,
        (PVOID)(ULONG_PTR)FALSE
    );

    if (!NT_SUCCESS(status)) {
        return VoidResult::err(ErrorCode::Unknown, "NtCreateEvent failed for stopEvent");
    }

    impl_->nexus.registerHandler(WhipOpcodes::LOADER_CONFIG, onLoaderConfig, &impl_->configCtx);

    return VoidResult::ok();
#ifdef VMP
    VMProtectEnd();
#endif
}

VoidResult LoaderIpcClient::connect(const std::string& host, uint16_t port) {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_connect");
#endif

    if (!impl_->nexus.connect(host.c_str(), port)) {
        return VoidResult::err(ErrorCode::ConnectionFailed, "Failed to connect to loader IPC server");
    }

    impl_->connected = true;
    return VoidResult::ok();
#ifdef VMP
    VMProtectEnd();
#endif
}

void LoaderIpcClient::disconnect() {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_disconnect");
#endif
    stopIpcThread();
    if (impl_->connected) {
        impl_->nexus.stopEventLoop();
        impl_->nexus.disconnect();
        impl_->connected = false;
    }
#ifdef VMP
    VMProtectEnd();
#endif
}

Result<LoaderConfig> LoaderIpcClient::receiveConfig(int timeoutMs) {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_receiveConfig");
#endif
    if (!impl_->connected) {
        return Result<LoaderConfig>::err(ErrorCode::ConnectionFailed, "Not connected to loader");
    }

    WORD ssn; PVOID addr;
    if (GetSyscallResolver().ResolveByName("NtResetEvent", ssn, addr)) {
        SyscallInvoker::Invoke(ssn, impl_->configCtx.completedEvent, nullptr);
    }
    impl_->configCtx.received = false;

    BinaryWriter readyWriter(64);
    readyWriter.writeInt(static_cast<i32>(0x60));
    readyWriter.writeString("ready");
    readyWriter.writeInt(0);

    bool sent = impl_->nexus.sendPacket(WhipOpcodes::CLIENT_LOAD_START, readyWriter.getData(), readyWriter.getSize());
    if (!sent) {
        return Result<LoaderConfig>::err(ErrorCode::SendFailed, "Failed to send ready signal to loader");
    }

    if (!isIpcThreadRunning()) {
        startIpcThread();
        Sleep(50);
    }

    if (!GetSyscallResolver().ResolveByName("NtWaitForSingleObject", ssn, addr)) {
        return Result<LoaderConfig>::err(ErrorCode::Unknown, "Failed to resolve NtWaitForSingleObject");
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)timeoutMs * 10000LL;

    NTSTATUS waitStatus = SyscallInvoker::Invoke(
        ssn,
        impl_->configCtx.completedEvent,
        (PVOID)(ULONG_PTR)FALSE,
        &timeout
    );

    if (waitStatus == 0x102) {
        return Result<LoaderConfig>::err(ErrorCode::Timeout, "Timeout waiting for LOADER_CONFIG");
    }

    if (waitStatus != 0) {
        return Result<LoaderConfig>::err(ErrorCode::Unknown, "Wait failed for LOADER_CONFIG");
    }

    if (!impl_->configCtx.received) {
        return Result<LoaderConfig>::err(ErrorCode::Unknown, "Config not received properly");
    }

    stopIpcThread();

    return Result<LoaderConfig>::ok(impl_->configCtx.config);
#ifdef VMP
    VMProtectEnd();
#endif
}

VoidResult LoaderIpcClient::sendLoadProgress(ClientLoadStage stage, const std::string& message, int percent) {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_sendLoadProgress");
#endif
    if (!impl_->connected) {
        return VoidResult::err(ErrorCode::ConnectionFailed, "Not connected");
    }

    BinaryWriter writer(512);
    writer.writeInt(static_cast<i32>(stage));
    writer.writeString(message.c_str());
    writer.writeInt(percent);

    u16 opcode = static_cast<u16>(static_cast<int>(stage));
    if (!impl_->nexus.sendPacket(opcode, writer.getData(), writer.getSize())) {
        return VoidResult::err(ErrorCode::SendFailed, "Failed to send load progress");
    }

    return VoidResult::ok();
#ifdef VMP
    VMProtectEnd();
#endif
}

VoidResult LoaderIpcClient::sendHeartbeat(int hooksActive, int errorsCount, bool serverConnected) {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_sendHeartbeat");
#endif
    if (!impl_->connected) {
        return VoidResult::err(ErrorCode::ConnectionFailed, "Not connected");
    }

    BinaryWriter writer(256);
    writer.writeLong(static_cast<i64>(time(nullptr)));
    writer.writeInt(hooksActive);
    writer.writeInt(errorsCount);
    writer.writeBool(serverConnected);

    if (!impl_->nexus.sendPacket(WhipOpcodes::CLIENT_HEARTBEAT, writer.getData(), writer.getSize())) {
        return VoidResult::err(ErrorCode::SendFailed, "Failed to send heartbeat");
    }

    return VoidResult::ok();
#ifdef VMP
    VMProtectEnd();
#endif
}

VoidResult LoaderIpcClient::sendDestruct(ClientDestructReason reason, const std::string& message) {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_sendDestruct");
#endif
    if (!impl_->connected) {
        return VoidResult::err(ErrorCode::ConnectionFailed, "Not connected");
    }

    BinaryWriter writer(512);
    writer.writeInt(static_cast<i32>(reason));
    writer.writeString(message.c_str());

    if (!impl_->nexus.sendPacket(WhipOpcodes::CLIENT_DESTRUCT, writer.getData(), writer.getSize())) {
        return VoidResult::err(ErrorCode::SendFailed, "Failed to send destruct request");
    }

    return VoidResult::ok();
#ifdef VMP
    VMProtectEnd();
#endif
}

bool LoaderIpcClient::isConnected() const {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_isConnected");
#endif
    return impl_->connected && impl_->nexus.isConnected();
#ifdef VMP
    VMProtectEnd();
#endif
}

bool LoaderIpcClient::isIpcThreadRunning() const {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_isIpcThreadRunning");
#endif
    bool running = InterlockedCompareExchange(&impl_->ipcThreadRunning, 0, 0) != 0;
#ifdef VMP
    VMProtectEnd();
#endif
    return running;
}

void LoaderIpcClient::startIpcThread() {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_startIpcThread");
#endif

    if (InterlockedCompareExchange(&impl_->ipcThreadRunning, 0, 0) != 0) {
#ifdef VMP
        VMProtectEnd();
#endif
        return;
    }

    if (!impl_->connected) {
#ifdef VMP
        VMProtectEnd();
#endif
        return;
    }

    InterlockedExchange(&impl_->ipcThreadRunning, 1);

    if (impl_->stopEvent) {
        WORD ssnReset; PVOID addrReset;
        if (GetSyscallResolver().ResolveByName("NtClearEvent", ssnReset, addrReset)) {
            SyscallInvoker::Invoke(ssnReset, impl_->stopEvent);
        }
    }

    WORD ssn; PVOID addr;
    if (!GetSyscallResolver().ResolveByName("NtCreateThreadEx", ssn, addr)) {
        InterlockedExchange(&impl_->ipcThreadRunning, 0);
#ifdef VMP
        VMProtectEnd();
#endif
        return;
    }

    NTSTATUS status = SyscallInvoker::Invoke(
        ssn,
        &impl_->ipcThread,
        (PVOID)(ULONG_PTR)THREAD_ALL_ACCESS,
        nullptr,
        GetCurrentProcess(),
        (PVOID)Impl::ipcThreadProc,
        impl_.get(),
        (PVOID)(ULONG_PTR)0,
        (PVOID)(ULONG_PTR)0,
        (PVOID)(ULONG_PTR)0,
        (PVOID)(ULONG_PTR)0,
        nullptr
    );

    if (!NT_SUCCESS(status) || !impl_->ipcThread) {
        InterlockedExchange(&impl_->ipcThreadRunning, 0);
    }

#ifdef VMP
    VMProtectEnd();
#endif
}

void LoaderIpcClient::stopIpcThread() {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_stopIpcThread");
#endif

    if (InterlockedCompareExchange(&impl_->ipcThreadRunning, 0, 0) == 0) {
#ifdef VMP
        VMProtectEnd();
#endif
        return;
    }

    InterlockedExchange(&impl_->ipcThreadRunning, 0);

    if (impl_->stopEvent) {
        WORD ssnEvent; PVOID addrEvent;
        if (GetSyscallResolver().ResolveByName("NtSetEvent", ssnEvent, addrEvent)) {
            SyscallInvoker::Invoke(ssnEvent, impl_->stopEvent, nullptr);
        }
    }

    if (impl_->ipcThread) {

        WORD ssn; PVOID addr;
        if (GetSyscallResolver().ResolveByName("NtWaitForSingleObject", ssn, addr)) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -5000000LL;

            NTSTATUS status = SyscallInvoker::Invoke(
                ssn,
                impl_->ipcThread,
                (PVOID)(ULONG_PTR)FALSE,
                &timeout
            );

            if (status == 0x102) {

                if (GetSyscallResolver().ResolveByName("NtTerminateThread", ssn, addr)) {
                    SyscallInvoker::Invoke(ssn, impl_->ipcThread, (PVOID)(ULONG_PTR)1);
                }
            }
        }

        if (GetSyscallResolver().ResolveByName("NtClose", ssn, addr)) {
            SyscallInvoker::Invoke(ssn, impl_->ipcThread);
        }
        impl_->ipcThread = nullptr;
    }

#ifdef VMP
    VMProtectEnd();
#endif
}

DWORD WINAPI LoaderIpcClient::Impl::ipcThreadProc(LPVOID param) {
#ifdef VMP
    VMProtectBeginUltra("LoaderIpcClient_ipcThreadProc");
#endif

    Impl* self = static_cast<Impl*>(param);

    while (InterlockedCompareExchange(&self->ipcThreadRunning, 0, 0) != 0) {
        if (!self->connected || !self->nexus.isConnected()) {
            break;
        }

        byte buffer[4096];
        u32 length = 0;
        u16 type = 0;

        if (self->nexus.receiveDecryptedPacket(type, buffer, &length, sizeof(buffer))) {

            if (type == WhipOpcodes::LOADER_CONFIG) {
                onLoaderConfig(type, buffer, length, &self->configCtx);
            }

        }

        if (self->stopEvent) {
            WORD ssn; PVOID addr;
            if (GetSyscallResolver().ResolveByName("NtWaitForSingleObject", ssn, addr)) {
                LARGE_INTEGER timeout;
                timeout.QuadPart = -100000LL;
                SyscallInvoker::Invoke(ssn, self->stopEvent, (PVOID)(ULONG_PTR)FALSE, &timeout);
            } else {
                Sleep(10);
            }
        } else {
            Sleep(10);
        }
    }

    InterlockedExchange(&self->ipcThreadRunning, 0);

#ifdef VMP
    VMProtectEnd();
#endif

    return 0;
}

#pragma optimize("", on)
