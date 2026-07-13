#include "auth/service/WhipAuthService.h"
#include "auth/protocol/PacketOpcodes.h"
#include "util/Debug.h"
#include "util/Inflate.h"
#include <whipnexus/SyscallManager.h>
#include <whipnexus/BinaryWriter.h>
#include <whipnexus/BinaryReader.h>
#include <new>
#include <intrin.h>

#include "util/xor.h"

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#include "antidebug/stack/stack_cpp.hpp"
#include "antidebug/vm/vm_cpp.hpp"

#pragma optimize("", off)

namespace {

inline uint32_t cachedRtKey() {
    static const uint32_t key = vm_runtime_key_stable();
    return key;
}

inline uint64_t encodeAuthFlag(uint32_t v) {
    auto cascade = ad::vm::ScoreCascade::from_key(cachedRtKey());
    return cascade.encode(v);
}

inline bool decodeAuthIsTrue(uint64_t encoded) {
    auto cascade = ad::vm::ScoreCascade::from_key(cachedRtKey());
    return cascade.decode(encoded) == 0u;
}

inline uint32_t decodeU32(uint64_t encoded) {
    auto cascade = ad::vm::ScoreCascade::from_key(cachedRtKey());
    return cascade.decode(encoded);
}

inline uint64_t mix64Local(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}
inline uint32_t computeAuthProof(const Byte sessionToken[32], const Byte userSecret[32]) {
    uint64_t h = 0xC0FFEE13DEADB33FULL;
    const uint64_t* st = reinterpret_cast<const uint64_t*>(sessionToken);
    const uint64_t* us = reinterpret_cast<const uint64_t*>(userSecret);
    for (int i = 0; i < 4; ++i) {
        h = mix64Local(h ^ st[i]);
        h = mix64Local(h ^ us[i]);
    }
    return static_cast<uint32_t>(h ^ (h >> 32));
}

inline bool authProofValid(const Byte sessionToken[32],
                           const Byte userSecret[32],
                           uint64_t clientAuthEncoded) {
    bool tokenAllZero = true;
    for (int i = 0; i < 32; ++i) {
        if (sessionToken[i] != 0) { tokenAllZero = false; break; }
    }
    if (tokenAllZero) return false;
    uint32_t expected = computeAuthProof(sessionToken, userSecret);
    return decodeU32(clientAuthEncoded) == expected;
}

inline void generateRequestId(WhipNexus* client, char outBuf[33]) {
    byte uuidBytes[16];
    client->generateRandomBytes(uuidBytes, 16);
    const char* hex = "0123456789abcdef";
    for (u32 i = 0; i < 16; i++) {
        outBuf[i * 2]     = hex[(uuidBytes[i] >> 4) & 0x0F];
        outBuf[i * 2 + 1] = hex[uuidBytes[i] & 0x0F];
    }
    outBuf[32] = '\0';
}

inline u32 strLen(const char* s) {
    u32 n = 0;
    if (s) while (s[n]) n++;
    return n;
}

}

bool WhipAuthService::computeAuthHmac(u16 opcode, const char* requestId, i64 timestamp, byte* hmacOut) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_computeAuthHmac");
#endif
    if (!decodeAuthIsTrue(hasUserSecretEncoded_)) return false;

    u32 reqIdLen = strLen(requestId);

    u32 dataLen = 2 + reqIdLen + 8;
    byte dataBuf[512];
    if (dataLen > sizeof(dataBuf)) return false;

    dataBuf[0] = (byte)((opcode >> 8) & 0xFF);
    dataBuf[1] = (byte)(opcode & 0xFF);
    SyscallManager::SecureMemCpy(dataBuf + 2, requestId, reqIdLen);

    u32 offset = 2 + reqIdLen;
    dataBuf[offset++] = (byte)((timestamp >> 56) & 0xFF);
    dataBuf[offset++] = (byte)((timestamp >> 48) & 0xFF);
    dataBuf[offset++] = (byte)((timestamp >> 40) & 0xFF);
    dataBuf[offset++] = (byte)((timestamp >> 32) & 0xFF);
    dataBuf[offset++] = (byte)((timestamp >> 24) & 0xFF);
    dataBuf[offset++] = (byte)((timestamp >> 16) & 0xFF);
    dataBuf[offset++] = (byte)((timestamp >> 8) & 0xFF);
    dataBuf[offset++] = (byte)(timestamp & 0xFF);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                     BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        return false;
    }

    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, userSecret_.data, 32, 0) == 0) {
        if (BCryptHashData(hHash, dataBuf, offset, 0) == 0) {
            if (BCryptFinishHash(hHash, hmacOut, 32, 0) == 0) {
                ok = true;
            }
        }
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
#ifdef VMP
    VMProtectEnd();
#endif
}

void WhipAuthService::enableCertificatePinning() {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_enableCertificatePinning");
#endif
    static constexpr byte pinnedCertificateHash[32] = {
        0xb6, 0x9e, 0x14, 0x43, 0x48, 0x63, 0x53, 0x00,
        0x2c, 0x88, 0x78, 0x43, 0xf3, 0xfe, 0x20, 0x53,
        0xc0, 0x28, 0x73, 0x65, 0x88, 0x5d, 0x69, 0xb7,
        0x9d, 0xc8, 0x95, 0xed, 0xc2, 0x07, 0xb2, 0xfa
    };

    client_->setCertificatePinning(true, pinnedCertificateHash);
#ifdef VMP
    VMProtectEnd();
#endif
}

WhipAuthService::WhipAuthService(const char* host, u16 port)
    : serverHost_(host), serverPort_(port), heartbeatRunning_(0),
      heartbeatThread_(nullptr), heartbeatStopEvent_(nullptr), heartbeatIntervalMs_(30000),
      onSessionExpired_(nullptr),
      clientAuthEncoded_(encodeAuthFlag(0xFFu)),
      hasUserSecretEncoded_(encodeAuthFlag(0xFFu)) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_ctor");
#endif
    pcName_[0] = '\0';
    executablePath_[0] = '\0';
    username_[0] = '\0';
    SyscallManager::SecureMemSet(userSecret_.data, 0, 32);
    SyscallManager::SecureMemSet(temporaryClientToken_.data, 0, 32);

    client_ = (WhipNexus*)SyscallManager::GetWrappers()->HeapAlloc(sizeof(WhipNexus));
    if (client_) new (client_) WhipNexus();

    heartbeatStopEvent_ = CreateEventA(nullptr, TRUE, FALSE, nullptr);

    SyscallManager::SecureMemSet(&fileContext_, 0, sizeof(fileContext_));
    fileContext_.completedEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    fileContext_.fileData = nullptr;

    SyscallManager::SecureMemSet(&heartbeatContext_, 0, sizeof(heartbeatContext_));
    heartbeatContext_.completedEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);

    SyscallManager::SecureMemSet(&configContext_, 0, sizeof(configContext_));
    configContext_.completedEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    configContext_.responseData = nullptr;

    if (client_) {
        client_->registerHandler(WhipOpcodes::KEYED_FILE_RESPONSE, onFileResponse, &fileContext_);
        client_->registerHandler(WhipOpcodes::HEARTBEAT_ACK, onHeartbeatAck, &heartbeatContext_);
        client_->registerHandler(WhipOpcodes::CONFIG_RESPONSE, onConfigResponse, &configContext_);
        client_->registerHandler(WhipOpcodes::SESSION_CRASH, onSessionCrash, nullptr);
        client_->registerHandler(WhipOpcodes::SESSION_REVOKED, onSessionRevoked, nullptr);
    }
#ifdef VMP
    VMProtectEnd();
#endif
}

WhipAuthService::~WhipAuthService() {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_dtor");
#endif

    logout();

    if (heartbeatStopEvent_) {
        SyscallManager::GetWrappers()->CloseHandle(heartbeatStopEvent_);
    }
    if (fileContext_.completedEvent) {
        SyscallManager::GetWrappers()->CloseHandle(fileContext_.completedEvent);
    }
    if (fileContext_.fileData) {
        SyscallManager::GetWrappers()->HeapFree(fileContext_.fileData);
    }
    if (heartbeatContext_.completedEvent) {
        SyscallManager::GetWrappers()->CloseHandle(heartbeatContext_.completedEvent);
    }
    if (configContext_.completedEvent) {
        SyscallManager::GetWrappers()->CloseHandle(configContext_.completedEvent);
    }
    if (configContext_.responseData) {
        SyscallManager::GetWrappers()->HeapFree(configContext_.responseData);
    }
    if (client_) {
        client_->~WhipNexus();
        SyscallManager::GetWrappers()->HeapFree(client_);
    }

#ifdef VMP
    VMProtectEnd();
#endif
}

VoidResult WhipAuthService::authenticate(const AuthPayload& payload) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_authenticate");
#endif
    ad::StackHidden _ad_guard;
    if (!payload.isValid()) {
        return VoidResult::err(ErrorCode::InvalidCredentials, "Invalid auth payload");
    }

    if (payload.machine.pcName.data) {
        SyscallManager::SecureMemCpy(pcName_, payload.machine.pcName.data, SyscallManager::StrLen(payload.machine.pcName.data) + 1);
        if (SyscallManager::StrLen(payload.machine.pcName.data) >= sizeof(pcName_)) pcName_[sizeof(pcName_) - 1] = '\0';
    }
    if (payload.machine.executablePath.data) {
        SyscallManager::SecureMemCpy(executablePath_, payload.machine.executablePath.data, SyscallManager::StrLen(payload.machine.executablePath.data) + 1);
        if (SyscallManager::StrLen(payload.machine.executablePath.data) >= sizeof(executablePath_)) executablePath_[sizeof(executablePath_) - 1] = '\0';
    }

    if (!client_->init()) {
        return VoidResult::err(ErrorCode::NetworkError, "WhipNexus init failed");
    }

    enableCertificatePinning();

    if (!client_->connect(serverHost_.data, serverPort_)) {
        return VoidResult::err(ErrorCode::ConnectionFailed, XOR("Connection failed"));
    }

    {
        BinaryWriter writer(1024);
        writer.writeBool(true);
        writer.writeString(payload.machine.hwid.data);
        writer.writeString(payload.machine.hwid.data);
        writer.writeString(payload.machine.pcName.data);
        writer.writeString(payload.machine.os.data);
        writer.writeString(payload.machine.executablePath.data);
        writer.writeLong((i64)SyscallManager::GetWrappers()->GetSystemTime());
        writer.writeLong(0); // authTag placeholder (server expects this slot)
        writer.writeString(payload.machine.gpuName.data);
        writer.writeString(payload.machine.cpuBrand.data);
        writer.writeString(payload.machine.ramHex.data);
        writer.writeString(payload.machine.boardModel.data);
        writer.writeString(payload.machine.screenInfo.data);
        writer.writeString(payload.machine.storageInfo.data);

        if (!client_->sendPacket(WhipOpcodes::INIT_REQUEST, writer.getData(), writer.getSize())) {
            return VoidResult::err(ErrorCode::AuthError, "Failed to send INIT_REQUEST");
        }
    }

    char selectedProductCode[64] = {};
    {
        byte respBuf[8192];
        u32 respLen = 0;
        u16 respOpcode = 0;
        if (!client_->receiveDecryptedPacket(respOpcode, respBuf, &respLen, sizeof(respBuf))) {
            return VoidResult::err(ErrorCode::AuthError, "Failed to receive INIT_RESPONSE");
        }
        if (respOpcode != WhipOpcodes::INIT_RESPONSE) {
            return VoidResult::err(ErrorCode::AuthError, "Unexpected INIT_RESPONSE opcode");
        }

        BinaryReader reader(respBuf, respLen);
        bool success = reader.readBool();

        char usernameBuf[256];
        reader.readString(usernameBuf, sizeof(usernameBuf));

        if (!success) {
            return VoidResult::err(ErrorCode::AuthError, usernameBuf);
        }

        SyscallManager::SecureMemCpy(username_, usernameBuf, sizeof(username_) - 1);
        username_[sizeof(username_) - 1] = '\0';

        i32 productCount = reader.readInt();
        if (productCount <= 0) {
            return VoidResult::err(ErrorCode::NoMatchingProduct, "No products available");
        }

        reader.readString(selectedProductCode, sizeof(selectedProductCode));
        char nameBuf[256], descBuf[512];
        reader.readString(nameBuf, sizeof(nameBuf));
        reader.readString(descBuf, sizeof(descBuf));
        reader.readLong();
        reader.readBool();

    }

    {
        BinaryWriter writer(256);
        writer.writeString(selectedProductCode);
        writer.writeString(payload.machine.pcName.data);
        writer.writeString(payload.machine.executablePath.data);
        writer.writeLong((i64)SyscallManager::GetWrappers()->GetSystemTime());

        if (!client_->sendPacket(WhipOpcodes::PRODUCT_SELECT, writer.getData(), writer.getSize())) {
            return VoidResult::err(ErrorCode::AuthError, "Failed to send PRODUCT_SELECT");
        }
    }

    SecureValue<32> sessionTokenBytes;
    SecureValue<32> challengeBytes;
    i32 permissions = 0;
    i64 expiresAt = 0;
    {
        byte respBuf[2048];
        u32 respLen = 0;
        u16 respOpcode = 0;
        if (!client_->receiveDecryptedPacket(respOpcode, respBuf, &respLen, sizeof(respBuf))) {
            return VoidResult::err(ErrorCode::AuthError, "Failed to receive AUTH_RESPONSE");
        }
        if (respOpcode != WhipOpcodes::AUTH_RESPONSE) {
            return VoidResult::err(ErrorCode::AuthError, "Unexpected AUTH_RESPONSE opcode");
        }

        BinaryReader reader(respBuf, respLen);
        bool success = reader.readBool();
        if (!success) {
            return VoidResult::err(ErrorCode::AuthError, "Auth rejected");
        }

        reader.readFixedBytes(sessionTokenBytes.data, 32);
        permissions = reader.readInt();
        expiresAt = reader.readLong();
        reader.readFixedBytes(challengeBytes.data, 32);

        if (reader.remaining() >= 32) {
            reader.readFixedBytes(temporaryClientToken_.data, 32);
        }
        if (reader.remaining() >= 32) {
            reader.readFixedBytes(userSecret_.data, 32);
            hasUserSecretEncoded_ = encodeAuthFlag(0u);
        }
    }

    clientAuthEncoded_ = encodeAuthFlag(
        computeAuthProof(sessionTokenBytes.data, userSecret_.data));

    sessionManager_.createSession(
        username_,
        sessionTokenBytes.data,
        challengeBytes.data,
        static_cast<u32>(permissions),
        expiresAt
    );
    return VoidResult::ok();
#ifdef VMP
    VMProtectEnd();
#endif
}

VoidResult WhipAuthService::authenticateWithToken(const Byte* temporaryClientToken, const Byte* clientAttestationKey, uint64_t loaderAuthTag, const char* hwid, const char* pcName, const char* executablePath) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_authenticateWithToken");
#endif
    ad::StackHidden _ad_guard;

#define AWL_LOG(fmt, ...) debug_Print("[CLIENT_AUTH] " fmt, ##__VA_ARGS__)

    AWL_LOG("START hwid=%s pcName=%s", hwid ? hwid : "null", pcName ? pcName : "null");
    AWL_LOG("temporaryClientToken[0..3]=%02X%02X%02X%02X",
        temporaryClientToken[0], temporaryClientToken[1],
        temporaryClientToken[2], temporaryClientToken[3]);
    AWL_LOG("loaderAuthTag=0x%016llX", (unsigned long long)loaderAuthTag);

    if (pcName) {
        SyscallManager::SecureMemCpy(pcName_, pcName, SyscallManager::StrLen(pcName) + 1);
        if (SyscallManager::StrLen(pcName) >= sizeof(pcName_)) pcName_[sizeof(pcName_) - 1] = '\0';
    }
    if (executablePath) {
        SyscallManager::SecureMemCpy(executablePath_, executablePath, SyscallManager::StrLen(executablePath) + 1);
        if (SyscallManager::StrLen(executablePath) >= sizeof(executablePath_)) executablePath_[sizeof(executablePath_) - 1] = '\0';
    }

    if (!client_->init()) {
        AWL_LOG("FAIL: WhipNexus init failed");
        return VoidResult::err(ErrorCode::NetworkError, "WhipNexus init failed");
    }
    AWL_LOG("init OK");

    enableCertificatePinning();

    if (!client_->connect(serverHost_.data, serverPort_)) {
        AWL_LOG("FAIL: connect failed host=%s port=%u", serverHost_.data, (unsigned)serverPort_);
        return VoidResult::err(ErrorCode::ConnectionFailed, XOR("Connection failed"));
    }
    AWL_LOG("connect OK");

    BinaryWriter writer(512);
    writer.writeFixedBytes(temporaryClientToken, 32);
    AWL_LOG("after writeFixedBytes(token) writerSize=%u", writer.getSize());

    writer.writeFixedBytes(clientAttestationKey, 32);
    AWL_LOG("after writeFixedBytes(attestation) writerSize=%u", writer.getSize());

    writer.writeString(hwid);
    writer.writeString(pcName);
    writer.writeString(executablePath);
    AWL_LOG("after writeStrings writerSize=%u", writer.getSize());

    i64 timestamp = (i64)SyscallManager::GetWrappers()->GetSystemTime();
    AWL_LOG("timestamp=%lld (0x%016llX)", (long long)timestamp, (unsigned long long)timestamp);
    writer.writeLong(timestamp);
    AWL_LOG("after writeLong(timestamp) writerSize=%u", writer.getSize());

    writer.writeLong(static_cast<i64>(loaderAuthTag));
    AWL_LOG("after writeLong(authTag) writerSize=%u totalPacket=%u", writer.getSize(), writer.getSize());

    // Dump bytes autour du timestamp (offset 269-276) pour vérifier ce qui est vraiment envoyé
    {
        const unsigned char* d = (const unsigned char*)writer.getData();
        u32 sz = writer.getSize();
        if (sz >= 277) {
            AWL_LOG("bytes[265..284]= %02X %02X %02X %02X | %02X %02X %02X %02X %02X %02X %02X %02X | %02X %02X %02X %02X %02X %02X %02X %02X",
                d[265],d[266],d[267],d[268],
                d[269],d[270],d[271],d[272],d[273],d[274],d[275],d[276], // timestamp
                d[277],d[278],d[279],d[280],d[281],d[282],d[283],d[284]);
        }
    }

    if (!client_->sendPacket(WhipOpcodes::CLIENT_AUTH, writer.getData(), writer.getSize())) {
        AWL_LOG("FAIL: sendPacket CLIENT_AUTH failed");
        return VoidResult::err(ErrorCode::AuthError, XOR("Failed to send CLIENT_AUTH"));
    }
    AWL_LOG("sendPacket CLIENT_AUTH OK");

    byte respBuf[65535];
    u32 respLen = 0;
    u16 respOpcode = 0;
    if (!client_->receiveDecryptedPacket(respOpcode, respBuf, &respLen, sizeof(respBuf))) {
        AWL_LOG("FAIL: receiveDecryptedPacket failed");
        return VoidResult::err(ErrorCode::AuthError, XOR("Failed to receive CLIENT_AUTH_RESPONSE"));
    }
    AWL_LOG("receiveDecryptedPacket opcode=0x%04X len=%u", (unsigned)respOpcode, (unsigned)respLen);

    if (respOpcode != WhipOpcodes::CLIENT_AUTH_RESPONSE) {
        AWL_LOG("FAIL: unexpected opcode 0x%04X", (unsigned)respOpcode);
        return VoidResult::err(ErrorCode::AuthError, "Unexpected response type");
    }

    BinaryReader reader(respBuf, respLen);
    bool success = reader.readBool();
    if (!success) {
        char errorBuf[512];
        if (reader.remaining() > 0) {
            reader.readString(errorBuf, sizeof(errorBuf));
            AWL_LOG("FAIL: CLIENT_AUTH rejected: %s", errorBuf);
            return VoidResult::err(ErrorCode::AuthError, errorBuf);
        }
        AWL_LOG("FAIL: CLIENT_AUTH rejected (no message)");
        return VoidResult::err(ErrorCode::AuthError, "CLIENT_AUTH rejected");
    }

    char usernameBuf[256];
    reader.readString(usernameBuf, sizeof(usernameBuf));
    AWL_LOG("SUCCESS: username=%s", usernameBuf);
    SyscallManager::SecureMemCpy(username_, usernameBuf, sizeof(username_) - 1);
    username_[sizeof(username_) - 1] = '\0';

    SecureValue<32> tokenBytes;
    reader.readFixedBytes(tokenBytes.data, 32);

    i32 permissions = reader.readInt();
    i64 expiresAt = reader.readLong();

    SecureValue<32> challenge;
    reader.readFixedBytes(challenge.data, 32);

    if (reader.remaining() >= 32) {
        reader.readFixedBytes(userSecret_.data, 32);
        hasUserSecretEncoded_ = encodeAuthFlag(0u);
    }

    clientAuthEncoded_ = encodeAuthFlag(
        computeAuthProof(tokenBytes.data, userSecret_.data));

    sessionManager_.createSession(
        usernameBuf,
        tokenBytes.data,
        challenge.data,
        static_cast<u32>(permissions),
        expiresAt
    );

#undef AWL_LOG
    return VoidResult::ok();
#ifdef VMP
    VMProtectEnd();
#endif
}

VoidResult WhipAuthService::sendMachineInfo(const char* mcUsername, const char* pcName) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_sendMachineInfo");
#endif
    if (!sessionManager_.hasActiveSession()) {
        return VoidResult::err(ErrorCode::SessionInvalid, "No active session");
    }

    const SessionInfo* session = sessionManager_.currentSession();
    if (!session) {
        return VoidResult::err(ErrorCode::SessionInvalid, "No session info");
    }

    BinaryWriter writer(512);
    writer.writeFixedBytes(session->sessionToken.data, 32);
    writer.writeString(mcUsername);
    writer.writeString(pcName);

    i64 timestamp = (i64)SyscallManager::GetWrappers()->GetSystemTime();
    writer.writeLong(timestamp);

    char requestIdBuf[33];
    generateRequestId(client_, requestIdBuf);
    writer.writeString(requestIdBuf);

    if (decodeAuthIsTrue(hasUserSecretEncoded_)) {
        SecureValue<32> authHmac;
        if (computeAuthHmac(WhipOpcodes::MACHINE_INFO, requestIdBuf, timestamp, authHmac.data)) {
            writer.writeFixedBytes(authHmac.data, 32);
        }
    }

    if (!client_->sendPacket(WhipOpcodes::MACHINE_INFO, writer.getData(), writer.getSize())) {
        return VoidResult::err(ErrorCode::SendFailed, "Failed to send MACHINE_INFO");
    }

    byte respBuf[512];
    u32 respLen = 0;
    u16 respOpcode = 0;
    if (!client_->receiveDecryptedPacket(respOpcode, respBuf, &respLen, sizeof(respBuf))) {
        return VoidResult::err(ErrorCode::Timeout, "Failed to receive MACHINE_INFO_RESPONSE");
    }

    if (respOpcode != WhipOpcodes::MACHINE_INFO_RESPONSE) {
        return VoidResult::err(ErrorCode::Unknown, "Unexpected response type");
    }

    BinaryReader reader(respBuf, respLen);
    bool success = reader.readBool();

    if (!success) {
        return VoidResult::err(ErrorCode::Unknown, "MACHINE_INFO rejected");
    }

    return VoidResult::ok();
#ifdef VMP
    VMProtectEnd();
#endif
}

VoidResult WhipAuthService::sendReverseDetected(uint32_t score, uint32_t checksRun, uint32_t checksHit,
                                                uint32_t checkMask, uint32_t flags, const char* reportText,
                                                const std::vector<std::vector<uint8_t>>* screenshots) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_sendReverseDetected");
#endif
    if (!sessionManager_.hasActiveSession()) {
        return VoidResult::err(ErrorCode::SessionInvalid, "No active session");
    }
    const SessionInfo* session = sessionManager_.currentSession();
    if (!session) {
        return VoidResult::err(ErrorCode::SessionInvalid, "No session info");
    }

    // Pre-compute screenshot payload size for BinaryWriter initial capacity.
    uint32_t shotCount = 0;
    uint32_t shotsBytes = 4; // screenshotCount field
    if (screenshots) {
        for (auto& s : *screenshots)
            if (!s.empty()) { shotsBytes += 4 + static_cast<uint32_t>(s.size()); ++shotCount; }
    }

    BinaryWriter writer(8192 + shotsBytes);
    writer.writeFixedBytes(session->sessionToken.data, 32);
    writer.writeInt(score);
    writer.writeInt(checksRun);
    writer.writeInt(checksHit);
    writer.writeInt(checkMask);
    writer.writeInt(flags);
    writer.writeString(reportText ? reportText : "");
    writer.writeString(pcName_);
    writer.writeString(executablePath_);

    i64 timestamp = (i64)SyscallManager::GetWrappers()->GetSystemTime();
    writer.writeLong(timestamp);

    char requestIdBuf[33];
    generateRequestId(client_, requestIdBuf);
    writer.writeString(requestIdBuf);

    if (decodeAuthIsTrue(hasUserSecretEncoded_)) {
        SecureValue<32> authHmac;
        if (computeAuthHmac(WhipOpcodes::REVERSE_DETECTED, requestIdBuf, timestamp, authHmac.data)) {
            writer.writeFixedBytes(authHmac.data, 32);
        }
    }

    // Screenshots: count(u32) + for each non-empty: len(u32) + bytes
    writer.writeInt(static_cast<int32_t>(shotCount));
    if (screenshots) {
        for (auto& s : *screenshots) {
            if (s.empty()) continue;
            writer.writeInt(static_cast<int32_t>(s.size()));
            writer.writeFixedBytes(s.data(), static_cast<uint32_t>(s.size()));
        }
    }

    if (!client_->sendPacket(WhipOpcodes::REVERSE_DETECTED, writer.getData(), writer.getSize())) {
        return VoidResult::err(ErrorCode::SendFailed, "Failed to send REVERSE_DETECTED");
    }

    return VoidResult::ok();
#ifdef VMP
    VMProtectEnd();
#endif
}

VoidResult WhipAuthService::sendHeartbeat() {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_sendHeartbeat");
#endif
    ad::StackHidden _ad_guard;
    bool sessActive = sessionManager_.hasActiveSession();
    const SessionInfo* sessInfo = sessionManager_.currentSession();
    if (sessInfo) {
    }
    if (!sessActive) {
        return VoidResult::err(ErrorCode::SessionInvalid, "No active session");
    }

    const SessionInfo* session = sessInfo;
    if (!session) {
        return VoidResult::err(ErrorCode::SessionInvalid, "No session info");
    }

    char requestIdBuf[33];
    generateRequestId(client_, requestIdBuf);

    i64 timestamp = (i64)SyscallManager::GetWrappers()->GetSystemTime();

    SecureValue<40> challengeAndTimestamp;
    SyscallManager::SecureMemCpy(challengeAndTimestamp.data, session->currentChallenge.data, 32);

    challengeAndTimestamp.data[32] = (byte)((timestamp >> 56) & 0xFF);
    challengeAndTimestamp.data[33] = (byte)((timestamp >> 48) & 0xFF);
    challengeAndTimestamp.data[34] = (byte)((timestamp >> 40) & 0xFF);
    challengeAndTimestamp.data[35] = (byte)((timestamp >> 32) & 0xFF);
    challengeAndTimestamp.data[36] = (byte)((timestamp >> 24) & 0xFF);
    challengeAndTimestamp.data[37] = (byte)((timestamp >> 16) & 0xFF);
    challengeAndTimestamp.data[38] = (byte)((timestamp >> 8) & 0xFF);
    challengeAndTimestamp.data[39] = (byte)(timestamp & 0xFF);

    SecureValue<32> challengeResponse;
    if (!client_->computeHmac(challengeAndTimestamp.data, 40, challengeResponse.data)) {
        return VoidResult::err(ErrorCode::SessionExpired, "Failed to compute challenge response");
    }

    BinaryWriter writer(512);
    writer.writeFixedBytes(session->sessionToken.data, 32);
    writer.writeLong(timestamp);
    writer.writeFixedBytes(challengeResponse.data, 32);
    writer.writeString(requestIdBuf);
    writer.writeString(pcName_);
    writer.writeString(executablePath_);

    if (!client_->isEventLoopRunning()) {
        client_->lockIO();

        if (!client_->sendPacket(WhipOpcodes::HEARTBEAT, writer.getData(), writer.getSize())) {
            client_->unlockIO();
            return VoidResult::err(ErrorCode::SessionExpired, XOR("Failed to send heartbeat"));
        }

        static const u32 HEARTBEAT_BUF_SIZE = 65536;
        byte* respBuf = (byte*)SyscallManager::GetWrappers()->HeapAlloc(HEARTBEAT_BUF_SIZE);
        if (!respBuf) {
            client_->unlockIO();
            return VoidResult::err(ErrorCode::Unknown, "Buffer allocation failed");
        }

        u16 respOpcode = 0;
        u32 respLen = 0;
        for (int attempts = 0; attempts < 5; attempts++) {
            respLen = 0;
            if (!client_->receiveDecryptedPacket(respOpcode, respBuf, &respLen, HEARTBEAT_BUF_SIZE)) {
                SyscallManager::GetWrappers()->HeapFree(respBuf);
                client_->unlockIO();
                return VoidResult::err(ErrorCode::Timeout, XOR("Failed to receive heartbeat ACK"));
            }
            if (respOpcode == WhipOpcodes::HEARTBEAT_ACK) break;

            client_->dispatchPacket(respOpcode, respBuf, respLen);
            if (attempts == 4) {
                SyscallManager::GetWrappers()->HeapFree(respBuf);
                client_->unlockIO();
                return VoidResult::err(ErrorCode::Unknown, "Too many non-heartbeat packets");
            }
        }

        BinaryReader hbReader(respBuf, respLen);
        bool hbSuccess = hbReader.readBool();
        if (!hbSuccess) {
            char errorMsg[256] = {};
            if (hbReader.remaining() > 0) hbReader.readString(errorMsg, sizeof(errorMsg));
            SyscallManager::GetWrappers()->HeapFree(respBuf);
            client_->unlockIO();
            return VoidResult::err(ErrorCode::SessionExpired, errorMsg);
        }

        SecureValue<32> nextChallenge;
        hbReader.readFixedBytes(nextChallenge.data, 32);
        hbReader.readLong();

        sessionManager_.updateHeartbeat(nextChallenge.data);
        SyscallManager::GetWrappers()->HeapFree(respBuf);
        client_->unlockIO();
        return VoidResult::ok();
    }

    SyscallManager::SecureMemSet(&heartbeatContext_.nextChallenge, 0,
                                 sizeof(heartbeatContext_.nextChallenge));
    heartbeatContext_.errorMessage[0] = '\0';
    heartbeatContext_.success = false;
    ResetEvent(heartbeatContext_.completedEvent);

    if (!client_->sendPacket(WhipOpcodes::HEARTBEAT, writer.getData(), writer.getSize())) {
        return VoidResult::err(ErrorCode::SessionExpired, XOR("Failed to send heartbeat"));
    }

    DWORD waitResult = WaitForSingleObject(heartbeatContext_.completedEvent, 10000);
    if (waitResult != WAIT_OBJECT_0) {
        return VoidResult::err(ErrorCode::Timeout, XOR("Heartbeat ACK timeout"));
    }

    if (!heartbeatContext_.success) {
        return VoidResult::err(ErrorCode::SessionExpired, heartbeatContext_.errorMessage);
    }

    sessionManager_.updateHeartbeat(heartbeatContext_.nextChallenge.data);
    return VoidResult::ok();
#ifdef VMP
    VMProtectEnd();
#endif
}

DWORD WINAPI WhipAuthService::heartbeatWorkerProc(LPVOID param) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_heartbeatWorkerProc");
#endif
    WhipAuthService* service = (WhipAuthService*)param;

    u32 iter = 0;
    while (InterlockedCompareExchange(&service->heartbeatRunning_, 0, 0) != 0) {
        DWORD waitResult = WaitForSingleObject(service->heartbeatStopEvent_, service->heartbeatIntervalMs_);
        if (waitResult == WAIT_OBJECT_0 || InterlockedCompareExchange(&service->heartbeatRunning_, 0, 0) == 0) {
            break;
        }

        ++iter;
        VoidResult result = service->sendHeartbeat();
        if (!result.isOk()) {
            service->sessionManager_.destroySession();
            if (service->onSessionExpired_) {
                service->onSessionExpired_();
            }
            break;
        }
    }
    return 0;
#ifdef VMP
    VMProtectEnd();
#endif
}

void WhipAuthService::onHeartbeatAck(u16 opcode, const byte* data, u32 length, void* ctx) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_onHeartbeatAck");
#endif
    auto* context = (HeartbeatAckContext*)ctx;

    BinaryReader reader(data, length);
    context->success = reader.readBool();

    if (context->success) {
        reader.readFixedBytes(context->nextChallenge.data, 32);
        reader.readLong();
    } else {
        if (reader.remaining() > 0) {
            reader.readString(context->errorMessage, sizeof(context->errorMessage));
        }
    }

    SetEvent(context->completedEvent);
#ifdef VMP
    VMProtectEnd();
#endif
}

void WhipAuthService::onFileResponse(u16 opcode, const byte* data, u32 length, void* ctx) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_onFileResponse");
#endif
    auto* context = (FileResponseContext*)ctx;

    BinaryReader reader(data, length);
    context->success = reader.readBool();

    if (!context->success) {
        reader.readBool();
        if (reader.remaining() >= 4) reader.readInt();
        if (reader.remaining() >= 4) reader.readInt();
        if (reader.remaining() > 0) {
            reader.readString(context->errorMessage, sizeof(context->errorMessage));
        }
        SetEvent(context->completedEvent);
#ifdef VMP
        VMProtectEnd();
#endif
        return;
    }

    bool compressed = reader.readBool();
    i32 originalSize   = reader.readInt();
    i32 compressedSize = reader.readInt();
    (void)compressedSize;

    byte tempBuf[655350];
    u32 wireLen = reader.readBytes(tempBuf, sizeof(tempBuf));

    if (compressed) {

        context->fileData = (byte*)SyscallManager::GetWrappers()->HeapAlloc((u32)originalSize + 1);
        if (!context->fileData) {
            context->success = false;
            SetEvent(context->completedEvent);
#ifdef VMP
            VMProtectEnd();
#endif
            return;
        }
        u32 inflatedLen = 0;
        bool ok = whip::inflateZlib(tempBuf, wireLen,
                                     context->fileData, (u32)originalSize,
                                     &inflatedLen);
        if (!ok || (i32)inflatedLen != originalSize) {
            SyscallManager::GetWrappers()->HeapFree(context->fileData);
            context->fileData = nullptr;
            context->success = false;
        } else {
            context->fileData[inflatedLen] = 0;
            context->dataLength = inflatedLen;
        }
    } else {
        context->fileData = (byte*)SyscallManager::GetWrappers()->HeapAlloc(wireLen + 1);
        if (context->fileData) {
            SyscallManager::SecureMemCpy(context->fileData, tempBuf, wireLen);
            context->fileData[wireLen] = 0;
            context->dataLength = wireLen;
        }
    }

    SetEvent(context->completedEvent);
#ifdef VMP
    VMProtectEnd();
#endif
}

Result<String> WhipAuthService::sendKeyedFileRequest(const char* key) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_sendKeyedFileRequest");
#endif
    ad::StackHidden _ad_guard;
    const SessionInfo* session = sessionManager_.currentSession();
    if (!session) {
        return Result<String>::err(ErrorCode::SessionExpired, "No session token");
    }

    BinaryWriter writer(1024);
    writer.writeFixedBytes(session->sessionToken.data, 32);
    writer.writeString(key);

    i64 timestamp = (i64)SyscallManager::GetWrappers()->GetSystemTime();
    writer.writeLong(timestamp);

    char requestIdBuf[33];
    generateRequestId(client_, requestIdBuf);
    writer.writeString(requestIdBuf);

    writer.writeString(pcName_);
    writer.writeString(executablePath_);

    if (decodeAuthIsTrue(hasUserSecretEncoded_)) {
        SecureValue<32> authHmac;
        if (computeAuthHmac(WhipOpcodes::KEYED_FILE_REQUEST, requestIdBuf, timestamp, authHmac.data)) {
            writer.writeFixedBytes(authHmac.data, 32);
        }
    }

    if (!client_->sendPacket(WhipOpcodes::KEYED_FILE_REQUEST, writer.getData(), writer.getSize())) {
        return Result<String>::err(ErrorCode::SendFailed, "Failed to send keyed file request");
    }

    static constexpr u32 MAX_RESP = 4u * 1024u * 1024u;
    byte* respBuf = (byte*)SyscallManager::GetWrappers()->HeapAlloc(MAX_RESP);
    if (!respBuf) {
        return Result<String>::err(ErrorCode::Unknown, "Allocation failed");
    }

    u16 respOpcode = 0;
    u32 respLen = 0;
    if (!client_->receiveDecryptedPacket(respOpcode, respBuf, &respLen, MAX_RESP)) {
        SyscallManager::GetWrappers()->HeapFree(respBuf);
        return Result<String>::err(ErrorCode::Timeout, "Failed to receive file response");
    }

    if (respOpcode != WhipOpcodes::KEYED_FILE_RESPONSE) {
        SyscallManager::GetWrappers()->HeapFree(respBuf);
        return Result<String>::err(ErrorCode::FileError, "Unexpected response type");
    }

    BinaryReader reader(respBuf, respLen);
    bool success = reader.readBool();
    if (!success) {
        reader.readBool();
        if (reader.remaining() >= 4) reader.readInt();
        if (reader.remaining() >= 4) reader.readInt();
        char errorMsg[512] = {};
        if (reader.remaining() > 0) reader.readString(errorMsg, sizeof(errorMsg));
        SyscallManager::GetWrappers()->HeapFree(respBuf);
        return Result<String>::err(ErrorCode::FileError, errorMsg);
    }
    bool compressed = reader.readBool();
    i32 originalSize = reader.readInt();
    i32 compressedSize = reader.readInt();
    (void)compressedSize;

    byte* fileData = (byte*)SyscallManager::GetWrappers()->HeapAlloc(MAX_RESP);
    if (!fileData) {
        SyscallManager::GetWrappers()->HeapFree(respBuf);
        return Result<String>::err(ErrorCode::Unknown, "File allocation failed");
    }

    u32 wireLen = reader.readBytes(fileData, MAX_RESP);
    SyscallManager::GetWrappers()->HeapFree(respBuf);
    if (wireLen == 0) {
        SyscallManager::GetWrappers()->HeapFree(fileData);
        return Result<String>::err(ErrorCode::FileError, "No data received");
    }

    u32 dataLen;
    if (compressed) {

        byte* inflated = (byte*)SyscallManager::GetWrappers()->HeapAlloc((u32)originalSize + 1);
        if (!inflated) {
            SyscallManager::GetWrappers()->HeapFree(fileData);
            return Result<String>::err(ErrorCode::Unknown, "Inflate allocation failed");
        }
        u32 inflatedLen = 0;
        bool ok = whip::inflateZlib(fileData, wireLen,
                                     inflated, (u32)originalSize, &inflatedLen);
        SyscallManager::GetWrappers()->HeapFree(fileData);
        if (!ok || (i32)inflatedLen != originalSize) {
            SyscallManager::GetWrappers()->HeapFree(inflated);
            return Result<String>::err(ErrorCode::FileError, "Inflate failed");
        }
        fileData = inflated;
        dataLen = inflatedLen;
    } else {
        dataLen = wireLen;
    }

    String result;
    result.data = (char*)fileData;
    result.length = (u16)dataLen;

    return Result<String>::ok(result);
#ifdef VMP
    VMProtectEnd();
#endif
}

Result<String> WhipAuthService::requestMappings(const char* version, const char* platform) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_requestMappings");
#endif
    ad::StackHidden _ad_guard;
    {
        const SessionInfo* s = sessionManager_.currentSession();
        if (!s || !authProofValid(s->sessionToken.data, userSecret_.data, clientAuthEncoded_)) {
            return Result<String>::err(ErrorCode::SessionExpired, "Not authenticated");
        }
    }

    char key[256];
    SyscallManager::SecureMemSet(key, 0, sizeof(key));

    u32 offset = 0;
    const char* prefix = "mappings-";
    while (*prefix && offset < sizeof(key) - 1) {
        key[offset++] = *prefix++;
    }

    const char* v = version;
    while (*v && offset < sizeof(key) - 1) {
        key[offset++] = *v++;
    }

    if (offset < sizeof(key) - 1) key[offset++] = '-';

    const char* p = platform;
    while (*p && offset < sizeof(key) - 1) {
        key[offset++] = *p++;
    }

    key[offset] = '\0';
    return sendKeyedFileRequest(key);
#ifdef VMP
    VMProtectEnd();
#endif
}

void WhipAuthService::onConfigResponse(u16 opcode, const byte* data, u32 length, void* ctx) {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_onConfigResponse");
#endif

    auto* context = (ConfigResponseContext*)ctx;

    if (context->responseData) {
        SyscallManager::GetWrappers()->HeapFree(context->responseData);
        context->responseData = nullptr;
    }

    context->responseData = (byte*)SyscallManager::GetWrappers()->HeapAlloc(length);
    if (context->responseData) {
        SyscallManager::SecureMemCpy(context->responseData, data, length);
        context->responseLength = length;
        context->received = true;
    } else {
        context->responseLength = 0;
        context->received = false;
    }

    SetEvent(context->completedEvent);
#ifdef VMP
    VMProtectEnd();
#endif
}

void WhipAuthService::onSessionCrash(u16 , const byte* ,
                                       u32 , void* ) {

#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_onSessionCrash");
#endif
    __fastfail(0xDEADC0DE);
    TerminateProcess(GetCurrentProcess(), 0xC0000005);
    ExitProcess(0xC0000005);
#ifdef VMP
    VMProtectEnd();
#endif
}

void WhipAuthService::onSessionRevoked(u16 , const byte* ,
                                         u32 , void* ) {

#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_onSessionRevoked");
#endif
    __fastfail(0xDEADC0DE);
    TerminateProcess(GetCurrentProcess(), 0xC0000005);
    ExitProcess(0xC0000005);
#ifdef VMP
    VMProtectEnd();
#endif
}

bool WhipAuthService::isAuthenticated() const {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_isAuthenticated");
#endif
    if (!sessionManager_.hasActiveSession()) return false;
    const SessionInfo* s = sessionManager_.currentSession();
    return s && authProofValid(s->sessionToken.data, userSecret_.data, clientAuthEncoded_);
#ifdef VMP
    VMProtectEnd();
#endif
}

void WhipAuthService::logout() {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_logout");
#endif

    stopHeartbeatLoop();

    if (client_) {
        client_->disconnect();
    }

    sessionManager_.destroySession();

    clientAuthEncoded_ = encodeAuthFlag(0xFFu);
#ifdef VMP
    VMProtectEnd();
#endif
}

Result<String> WhipAuthService::requestVersions() {
#ifdef VMP
    VMProtectBeginUltra("WhipAuthService_requestVersions");
#endif
    {
        const SessionInfo* s = sessionManager_.currentSession();
        if (!s || !authProofValid(s->sessionToken.data, userSecret_.data, clientAuthEncoded_)) {
            return Result<String>::err(ErrorCode::SessionExpired, "Not authenticated");
        }
    }
    return sendKeyedFileRequest("versions");
#ifdef VMP
    VMProtectEnd();
#endif
}

#pragma optimize("", on)
