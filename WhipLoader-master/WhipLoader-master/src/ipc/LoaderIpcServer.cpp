#pragma optimize("", off)
#include "ipc/LoaderIpcServer.h"
#include "network/PacketOpcodes.h"
#include "security/xor.h"
#include "security/SecureMemory.h"
#include "auth/Credentials.h"
#include <whipnexus/BinaryReader.h>
#include <whipnexus/BinaryWriter.h>
#include <whipsyscall/WhipSysCall.h>
#include <ctime>
#include <cstring>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

static SyscallResolver& GetResolver() {
    static SyscallResolver s_res;
    static bool s_init = s_res.Init();
    (void)s_init;
    return s_res;
}

// In bypass mode (loader mapped into Lunar/Electron), Chromium hooks half
// the ntdll Nt*/Zw* stubs to redirect them through its broker. SyscallResolver
// extracts the SSN from those stubs and produces wrong/missing values (Halo's
// Gate gap-fill fails on alphabetical clusters of hooked stubs). Going via
// plain Win32 lets the broker translate the request normally.

static inline HANDLE NtCreateManualEvent() {
#ifdef WHIP_BYPASS_MODE
    return CreateEventW(nullptr, TRUE /* manual reset */, FALSE, nullptr);
#else
    WORD ssn; PVOID addr;
    if (!GetResolver().ResolveByName("NtCreateEvent", ssn, addr)) return nullptr;
    HANDLE hEvent = nullptr;
    NTSTATUS s = SyscallInvoker::Invoke(
        ssn,
        &hEvent,
        reinterpret_cast<PVOID>((ULONG_PTR)0x1F0003),
        nullptr,
        reinterpret_cast<PVOID>((ULONG_PTR)0),
        reinterpret_cast<PVOID>((ULONG_PTR)FALSE)
    );
    return NT_SUCCESS(s) ? hEvent : nullptr;
#endif
}

static inline void NtSetEvt(HANDLE h) {
#ifdef WHIP_BYPASS_MODE
    if (h) SetEvent(h);
#else
    WORD ssn; PVOID addr;
    if (GetResolver().ResolveByName("NtSetEvent", ssn, addr))
        SyscallInvoker::Invoke(ssn, h, nullptr);
#endif
}

static inline void NtResetEvt(HANDLE h) {
#ifdef WHIP_BYPASS_MODE
    if (h) ResetEvent(h);
#else
    WORD ssn; PVOID addr;
    if (GetResolver().ResolveByName("NtResetEvent", ssn, addr))
        SyscallInvoker::Invoke(ssn, h, nullptr);
#endif
}

static inline bool NtWaitEvt(HANDLE h, DWORD timeoutMs) {
#ifdef WHIP_BYPASS_MODE
    return h && WaitForSingleObject(h, timeoutMs) == WAIT_OBJECT_0;
#else
    WORD ssn; PVOID addr;
    if (!GetResolver().ResolveByName("NtWaitForSingleObject", ssn, addr)) return false;
    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)timeoutMs * 10000LL;
    NTSTATUS s = SyscallInvoker::Invoke(
        ssn,
        h,
        reinterpret_cast<PVOID>((ULONG_PTR)FALSE),
        &timeout
    );
    return s == 0;
#endif
}

static inline void NtCloseHandle(HANDLE h) {
    if (!h) return;
#ifdef WHIP_BYPASS_MODE
    CloseHandle(h);
#else
    WORD ssn; PVOID addr;
    if (GetResolver().ResolveByName("NtClose", ssn, addr))
        SyscallInvoker::Invoke(ssn, h);
#endif
}

struct LoaderIpcServerImpl {
    WhipNexusServer server;
    bool initialized;

    OnClientLoadProgress onLoadProgress;
    OnClientHeartbeat    onHeartbeat;
    OnClientDestruct     onDestruct;

    u32    clientId;
    HANDLE configSentEvent;
    bool   configSendSuccess;

    bool configReady;
    SecureByteArray<32> configToken;
    SecureByteArray<32> configClientAttestationKey;
    char configServerHost[256];
    u16  configServerPort;
    char configHwid[128];
    u64  configAuthTag;

    LoaderIpcServerImpl() : initialized(false), onLoadProgress(nullptr),
        onHeartbeat(nullptr), onDestruct(nullptr), clientId(0),
        configSentEvent(nullptr), configSendSuccess(false),
        configReady(false), configServerPort(0), configAuthTag(0) {
        configServerHost[0] = '\0';
        configHwid[0] = '\0';
    }
};

struct LoaderIpcServer::Impl : LoaderIpcServerImpl {};

static void handleClientReady(u32 clientId, u16 opcode, const byte* data, u32 length, void* ctx) {
    auto* impl = static_cast<LoaderIpcServerImpl*>(ctx);
    impl->clientId = clientId;

    if (impl->configReady) {
        BinaryWriter writer(512);
        writer.writeFixedBytes(impl->configToken.data, 32);
        writer.writeFixedBytes(impl->configClientAttestationKey.data, 32);
        writer.writeString(impl->configServerHost);
        writer.writeShort(impl->configServerPort);
        writer.writeString(impl->configHwid);
        writer.writeLong(static_cast<i64>(time(nullptr)));
        writer.writeLong(static_cast<i64>(impl->configAuthTag));

        impl->configSendSuccess = impl->server.sendToClient(
            clientId, WhipOpcodes::LOADER_CONFIG, writer.getData(), writer.getSize());
    } else {
        impl->configSendSuccess = false;
    }

    if (impl->configSentEvent) {
        NtSetEvt(impl->configSentEvent);
    }
}

static void handleClientLoadProgress(u32 clientId, u16 opcode, const byte* data, u32 length, void* ctx) {
    auto* impl = static_cast<LoaderIpcServerImpl*>(ctx);
    impl->clientId = clientId;

    BinaryReader reader(data, length);
    i32 stage = reader.readInt();
    char msgBuf[512];
    reader.readString(msgBuf, sizeof(msgBuf));
    i32 percent = reader.readInt();

    if (impl->onLoadProgress) {
        ClientLoadProgress progress;
        progress.stage = static_cast<ClientLoadStage>(stage);
        authStrCopy(progress.message, msgBuf, sizeof(progress.message));
        progress.percent = percent;
        impl->onLoadProgress(&progress);
    }
}

static void handleClientHeartbeat(u32 clientId, u16 opcode, const byte* data, u32 length, void* ctx) {
    auto* impl = static_cast<LoaderIpcServerImpl*>(ctx);
    BinaryReader reader(data, length);
    reader.readLong();
    i32  hooksActive    = reader.readInt();
    i32  errorsCount    = reader.readInt();
    bool serverConnected = reader.readBool();

    if (impl->onHeartbeat) {
        ClientHeartbeatInfo info;
        info.hooksActive    = hooksActive;
        info.errorsCount    = errorsCount;
        info.serverConnected = serverConnected;
        impl->onHeartbeat(&info);
    }
}

static void handleClientDestruct(u32 clientId, u16 opcode, const byte* data, u32 length, void* ctx) {
    auto* impl = static_cast<LoaderIpcServerImpl*>(ctx);
    BinaryReader reader(data, length);
    i32 reason = reader.readInt();
    char msgBuf[512];
    reader.readString(msgBuf, sizeof(msgBuf));

    if (impl->onDestruct)
        impl->onDestruct(static_cast<ClientDestructReason>(reason), msgBuf);
}

LoaderIpcServer::LoaderIpcServer() {
    impl_ = new Impl();
}

LoaderIpcServer::~LoaderIpcServer() {
    stop();
    if (impl_ && impl_->configSentEvent) {
        NtCloseHandle(impl_->configSentEvent);
        impl_->configSentEvent = nullptr;
    }
    if (impl_) {
        delete impl_;
        impl_ = nullptr;
    }
}

VoidResult LoaderIpcServer::initialize() {
    if (!impl_->server.init())
        return VoidResult::err(ErrorCode::InitializationError, "Failed to init IPC server");

    if (!impl_->server.bind(XOR("127.0.0.1"), 47832))
        return VoidResult::err(ErrorCode::InitializationError, "Failed to bind IPC server");

    impl_->configSentEvent = NtCreateManualEvent();
    if (!impl_->configSentEvent)
        return VoidResult::err(ErrorCode::InitializationError, "Failed to create IPC config event");

    impl_->server.registerHandler(WhipOpcodes::CLIENT_LOAD_START,    handleClientReady,        impl_);
    impl_->server.registerHandler(WhipOpcodes::CLIENT_LOAD_AUTH,     handleClientLoadProgress, impl_);
    impl_->server.registerHandler(WhipOpcodes::CLIENT_LOAD_VERSIONS, handleClientLoadProgress, impl_);
    impl_->server.registerHandler(WhipOpcodes::CLIENT_LOAD_MAPPINGS, handleClientLoadProgress, impl_);
    impl_->server.registerHandler(WhipOpcodes::CLIENT_LOAD_HOOKS,    handleClientLoadProgress, impl_);
    impl_->server.registerHandler(WhipOpcodes::CLIENT_LOAD_COMPLETE, handleClientLoadProgress, impl_);
    impl_->server.registerHandler(WhipOpcodes::CLIENT_HEARTBEAT,     handleClientHeartbeat,    impl_);
    impl_->server.registerHandler(WhipOpcodes::CLIENT_DESTRUCT,      handleClientDestruct,     impl_);

    impl_->initialized = true;
    return VoidResult::ok();
}

VoidResult LoaderIpcServer::start() {
    if (!impl_->initialized)
        return VoidResult::err(ErrorCode::InvalidArgument, "IPC server not initialized");
    if (!impl_->server.start())
        return VoidResult::err(ErrorCode::NetworkError, "Failed to start IPC server");
    return VoidResult::ok();
}

void LoaderIpcServer::stop() {
    impl_->server.stop();
}

u16 LoaderIpcServer::getPort() const  { return impl_->server.getPort(); }
bool LoaderIpcServer::isRunning() const { return impl_->server.isRunning(); }

VoidResult LoaderIpcServer::sendConfig(
    const byte* temporaryClientToken,
    const byte* clientAttestationKey,
    const char* serverHost,
    u16 serverPort,
    const char* hwid,
    u64 authTag
) {
    memcpy(impl_->configToken.data, temporaryClientToken, 32);
    memcpy(impl_->configClientAttestationKey.data, clientAttestationKey, 32);
    authStrCopy(impl_->configServerHost, serverHost, sizeof(impl_->configServerHost));
    impl_->configServerPort = serverPort;
    authStrCopy(impl_->configHwid, hwid, sizeof(impl_->configHwid));
    impl_->configAuthTag = authTag;
    impl_->configSendSuccess = false;

    NtResetEvt(impl_->configSentEvent);
    impl_->configReady = true;

    if (!NtWaitEvt(impl_->configSentEvent, 15000)) {
        impl_->configReady = false;
        return VoidResult::err(ErrorCode::Timeout, "Client did not connect in time");
    }

    impl_->configReady = false;

    if (!impl_->configSendSuccess) {
        return VoidResult::err(ErrorCode::SendFailed, "Failed to send config to client");
    }

    return VoidResult::ok();
}

void LoaderIpcServer::setOnLoadProgress(OnClientLoadProgress callback) {
    impl_->onLoadProgress = callback;
}

void LoaderIpcServer::setOnHeartbeat(OnClientHeartbeat callback) {
    impl_->onHeartbeat = callback;
}

void LoaderIpcServer::setOnDestruct(OnClientDestruct callback) {
    impl_->onDestruct = callback;
}

#pragma optimize("", on)
