#pragma optimize("", off)
#include "network/WhipNexusClient.h"
#include "network/PacketOpcodes.h"
#include "auth/Credentials.h"
#include <whipnexus/WhipNexus.h>
#include <whipnexus/SyscallManager.h>
#include <whipnexus/BinaryWriter.h>
#include <whipnexus/BinaryReader.h>
#include <bcrypt.h>
#include <cstdio>
#include <ctime>
#include <memory>

#include "antidebug/vm/vm_cpp.hpp"
#include "util/Inflate.h"

namespace {
    // WhipVM ScoreCascade — encode 0 == "true" (authenticated / has secret).
    // Same pattern used by WhipClient::clientAuthEncoded_. The runtime key is
    // process-stable (PEB+TEB only) so cross-TU and cross-thread agree.
    inline u64 encodeAuthFlag(u32 v) {
        auto cascade = ad::vm::ScoreCascade::from_key(vm_runtime_key_stable());
        return cascade.encode(v);
    }
    inline bool decodeAuthIsTrue(u64 encoded) {
        auto cascade = ad::vm::ScoreCascade::from_key(vm_runtime_key_stable());
        return cascade.decode(encoded) == 0u;
    }

    // For values that are NOT booleans (e.g. permission bitmasks), reuse the
    // same cascade but return the round-tripped u32 directly. A reverser
    // patching the encoded u64 in memory cannot grant themselves new
    // permission bits without knowing the runtime ECDH key.
    inline u64 encodeU32(u32 v) {
        auto cascade = ad::vm::ScoreCascade::from_key(vm_runtime_key_stable());
        return cascade.encode(v);
    }
    inline u32 decodeU32(u64 encoded) {
        auto cascade = ad::vm::ScoreCascade::from_key(vm_runtime_key_stable());
        return cascade.decode(encoded);
    }

    // Auth proof: a 32-bit fingerprint of the server-derived sessionToken
    // and userSecret. SplitMix64 over a folded XOR of every 4-byte word in
    // both buffers, truncated to 32 bits. Properties used:
    //   1. Pre-auth: sessionToken/userSecret are zero → proof == fixed
    //      value of mix64(0). The encoded auth flag is initialized to a
    //      different sentinel, so isAuthenticated() rejects.
    //   2. Post-auth: proof depends on 64 bytes of server data the attacker
    //      cannot synthesize without performing a real handshake.
    //   3. Patching `authenticatedEncoded` to fake "true" requires the
    //      attacker to compute encodeU32(proof) at runtime, which itself
    //      depends on the WhipVM cascade key (PEB+TEB-derived).
    inline u64 mix64Local(u64 x) {
        x += 0x9E3779B97F4A7C15ULL;
        x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
        x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
        return x ^ (x >> 31);
    }
    inline u32 computeAuthProof(const byte sessionToken[32], const byte userSecret[32]) {
        u64 h = 0xC0FFEE13DEADB33FULL;
        const u64* st = reinterpret_cast<const u64*>(sessionToken);
        const u64* us = reinterpret_cast<const u64*>(userSecret);
        for (int i = 0; i < 4; ++i) {
            h = mix64Local(h ^ st[i]);
            h = mix64Local(h ^ us[i]);
        }
        return static_cast<u32>(h ^ (h >> 32));
    }

    // Shared check used by isAuthenticated(), sendHeartbeat(), requestFile().
    // Recomputes the auth proof from the live buffers and compares to the
    // encoded flag — patching only one of (token / encoded flag) desyncs.
    inline bool authProofValid(const byte sessionToken[32],
                               const byte userSecret[32],
                               u64 authenticatedEncoded) {
        bool tokenAllZero = true;
        for (int i = 0; i < 32; ++i) {
            if (sessionToken[i] != 0) { tokenAllZero = false; break; }
        }
        if (tokenAllZero) return false;
        u32 expected = computeAuthProof(sessionToken, userSecret);
        return decodeU32(authenticatedEncoded) == expected;
    }
}

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#include <Windows.h>

namespace {

// Parse un packet ERROR (0xFF) du serveur: int(code) + string(message)
// et retourne "Error #N" dans outMsg[32].
inline void parseErrorPacket(const byte* buf, u32 len, char outMsg[32]) {
    snprintf(outMsg, 32, "Error #0");
    if (len < 4) return;
    i32 code = ((i32)buf[0] << 24) | ((i32)buf[1] << 16) | ((i32)buf[2] << 8) | (i32)buf[3];
    snprintf(outMsg, 32, "Error #%d", code);
}

inline u32 strLen(const char* s) {
    u32 n = 0;
    if (s) while (s[n]) n++;
    return n;
}

inline void strCopy(char* dst, const char* src, u32 dstSize) {
    if (!dst || dstSize == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    u32 n = 0;
    while (src[n] && n < dstSize - 1) { dst[n] = src[n]; n++; }
    dst[n] = '\0';
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

inline bool computeAuthHmacInternal(const byte userSecret[32], u16 opcode,
                                     const char* requestId, i64 timestamp,
                                     byte hmacOut[32]) {
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
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, (PUCHAR)userSecret, 32, 0) == 0) {
        if (BCryptHashData(hHash, dataBuf, offset, 0) == 0) {
            if (BCryptFinishHash(hHash, hmacOut, 32, 0) == 0) {
                ok = true;
            }
        }
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

} // namespace

struct WhipNexusClient::Impl {
    WhipNexus* client;
    bool initialized;
    bool connected;

    // Server coordinates stored at connect() time. Used by sendReverseDetected
    // to open a fresh socket when the main connection is unavailable.
    char serverHost[256];
    u16  serverPort;

    // WhipVM-encoded auth flags. Decoded == 0 → flag is true.
    // NOPing a single read returns false (the encoded sentinel 0xFF decodes
    // to 0xFF), and forging the right encoded value requires the runtime
    // ECDH key (PEB+TEB-derived).
    u64 authenticatedEncoded;
    u64 hasUserSecretEncoded;

    char username[256];
    byte sessionToken[32];
    byte temporaryClientToken[32];
    byte clientAttestationToken[32];
    byte currentChallenge[32];
    byte userSecret[32];
    // permissions stored as the WhipVM cascade encoding of the original u32
    // bitmask. A reverser patching this in memory cannot grant themselves
    // admin/premium without knowing the runtime ECDH key (PEB+TEB-derived).
    u64 permissionsEncoded;
    i64 expiresAt;
    i32 lastErrorCode;

    // Liste des produits récupérés depuis INIT_RESPONSE
    LoaderProductInfo* products;
    i32 productCount;

    Impl()
        : client(nullptr), initialized(false), connected(false),
          serverPort(0),
          authenticatedEncoded(encodeAuthFlag(0xFFu)),
          hasUserSecretEncoded(encodeAuthFlag(0xFFu)),
          permissionsEncoded(encodeU32(0u)),  // empty bitmask, encoded
          expiresAt(0), lastErrorCode(0),
          products(nullptr), productCount(0) {
        username[0] = '\0';
        serverHost[0] = '\0';
        SyscallManager::SecureMemSet(sessionToken, 0, 32);
        SyscallManager::SecureMemSet(temporaryClientToken, 0, 32);
        SyscallManager::SecureMemSet(clientAttestationToken, 0, 32);
        SyscallManager::SecureMemSet(currentChallenge, 0, 32);
        SyscallManager::SecureMemSet(userSecret, 0, 32);
    }

    ~Impl() {
        if (products) { delete[] products; }
    }
};

VoidResult WhipNexusClient::requireClient() const {
    if (!impl_ || !impl_->client) {
        return VoidResult::err(ErrorCode::InvalidArgument, "WhipNexus client is null");
    }
    if (!impl_->initialized) {
        return VoidResult::err(ErrorCode::InvalidArgument, "WhipNexus client not initialized (call initialize() first)");
    }
    return VoidResult::ok();
}

VoidResult WhipNexusClient::requireConnected() const {
    auto check = requireClient();
    if (!check) { return check; }
    if (!impl_->connected) {
        return VoidResult::err(ErrorCode::ConnectionFailed, "Not connected to server (call connect() first)");
    }
    return VoidResult::ok();
}

WhipNexusClient::WhipNexusClient() {
    impl_ = new Impl();
    impl_->client = new WhipNexus();
}

WhipNexusClient::~WhipNexusClient() {
    if (!impl_) { return; }

    if (impl_->client) {
        if (impl_->connected) {
            impl_->client->disconnect();
            impl_->connected = false;
        }
        delete impl_->client;
        impl_->client = nullptr;
    }

    delete impl_;
    impl_ = nullptr;
}

VoidResult WhipNexusClient::initialize() {
    if (impl_->initialized) {
        return VoidResult::ok();
    }

    if (!impl_->client) {
        return VoidResult::err(ErrorCode::InitializationError, "WhipNexus client is null");
    }

    if (!impl_->client->init()) {
        return VoidResult::err(ErrorCode::InitializationError, "Failed to initialize WhipNexus crypto engine");
    }

    impl_->initialized = true;
    return VoidResult::ok();
}

void WhipNexusClient::setCertificatePinning(bool enabled, const Byte* certHash) {
    if (!impl_ || !impl_->client) {
        return;
    }
    impl_->client->setCertificatePinning(enabled, certHash);
}

VoidResult WhipNexusClient::connect(const char* host, u16 port) {
    auto check = requireClient();
    if (!check) { return check; }

    if (!impl_->client->connect(host, port)) {
        return VoidResult::err(ErrorCode::ConnectionFailed, "Failed to connect to server");
    }

    strCopy(impl_->serverHost, host, sizeof(impl_->serverHost));
    impl_->serverPort = port;
    impl_->connected = true;
    return VoidResult::ok();
}

VoidResult WhipNexusClient::performHandshake() {
    auto check = requireConnected();
    if (!check) { return check; }
    // Le handshake WHIP est désormais fait automatiquement par WhipNexus::connect().
    // Cette méthode est un no-op conservé pour compat API.
    return VoidResult::ok();
}

void WhipNexusClient::disconnect() {
    if (!impl_ || !impl_->client || !impl_->connected) {
        return;
    }

    impl_->client->disconnect();
    impl_->connected = false;
    impl_->authenticatedEncoded = encodeAuthFlag(0xFFu);  // not authenticated
}

VoidResult WhipNexusClient::initRequest(
    const char* identifier,
    bool useHwid,
    const char* hwid,
    const char* pcName,
    const char* os,
    const char* executablePath,
    u64 authTag,
    const char* gpuName,
    const char* cpuBrand,
    const char* ramHex,
    const char* boardModel,
    const char* screenInfo,
    const char* storageInfo
) {
    auto check = requireConnected();
    if (!check) { return check; }

    auto* nx = impl_->client;

    // ---- INIT_REQUEST ----
    {
        BinaryWriter writer(1024);
        writer.writeBool(useHwid);
        writer.writeString(identifier);
        writer.writeString(hwid);
        writer.writeString(pcName);
        writer.writeString(os);
        writer.writeString(executablePath);
        writer.writeLong((i64)time(nullptr));
        writer.writeLong(static_cast<i64>(authTag));
        writer.writeString(gpuName    ? gpuName    : "");
        writer.writeString(cpuBrand   ? cpuBrand   : "");
        writer.writeString(ramHex     ? ramHex     : "");
        writer.writeString(boardModel ? boardModel : "");
        writer.writeString(screenInfo ? screenInfo : "");
        writer.writeString(storageInfo? storageInfo: "");

        if (!nx->sendPacket(WhipOpcodes::INIT_REQUEST, writer.getData(), writer.getSize())) {
            return VoidResult::err(ErrorCode::AuthError, "Failed to send INIT_REQUEST");
        }
    }

    // ---- INIT_RESPONSE ----
    {
        byte respBuf[8192];
        u32 respLen = 0;
        u16 respOpcode = 0;
        if (!nx->receiveDecryptedPacket(respOpcode, respBuf, &respLen, sizeof(respBuf))) {
            return VoidResult::err(ErrorCode::AuthError, "Failed to receive INIT_RESPONSE");
        }
        if (respOpcode != WhipOpcodes::INIT_RESPONSE) {
            char errMsg[32];
            parseErrorPacket(respBuf, respLen, errMsg);
            return VoidResult::err(ErrorCode::AuthError,
                respOpcode == WhipOpcodes::ERROR_PACKET ? errMsg : "Unexpected INIT_RESPONSE opcode");
        }

        BinaryReader reader(respBuf, respLen);
        bool success = reader.readBool();

        char usernameBuf[256];
        reader.readString(usernameBuf, sizeof(usernameBuf));

        if (!success) {
            impl_->lastErrorCode = 0;
            int numEnd = 0;
            for (; numEnd < (int)strLen(usernameBuf) && numEnd < 10; numEnd++) {
                char c = usernameBuf[numEnd];
                if (c >= '0' && c <= '9')
                    impl_->lastErrorCode = impl_->lastErrorCode * 10 + (c - '0');
                else break;
            }
            if (usernameBuf[numEnd] == '|' && usernameBuf[numEnd + 1] != '\0')
                return VoidResult::err(ErrorCode::AuthError, usernameBuf + numEnd + 1);
            return VoidResult::err(ErrorCode::AuthError, "Init request rejected");
        }

        strCopy(impl_->username, usernameBuf, sizeof(impl_->username));

        // Liste des produits.
        if (impl_->products) { delete[] impl_->products; impl_->products = nullptr; }
        impl_->productCount = reader.readInt();
        if (impl_->productCount > 0) {
            impl_->products = new LoaderProductInfo[impl_->productCount];
            for (i32 i = 0; i < impl_->productCount; i++) {
                char codeBuf[64], nameBuf[256], descBuf[512];
                reader.readString(codeBuf, sizeof(codeBuf));
                reader.readString(nameBuf, sizeof(nameBuf));
                reader.readString(descBuf, sizeof(descBuf));
                strCopy(impl_->products[i].code, codeBuf, sizeof(impl_->products[i].code));
                strCopy(impl_->products[i].name, nameBuf, sizeof(impl_->products[i].name));
                strCopy(impl_->products[i].description, descBuf, sizeof(impl_->products[i].description));
                impl_->products[i].expiresAt = reader.readLong();
                impl_->products[i].lifetime = reader.readBool();
            }
        }
    }

    return VoidResult::ok();
}

VoidResult WhipNexusClient::selectProduct(const char* productCode, const char* pcName, const char* executablePath) {
    auto check = requireConnected();
    if (!check) { return check; }

    auto* nx = impl_->client;

    // ---- PRODUCT_SELECT ----
    {
        BinaryWriter writer(256);
        writer.writeString(productCode);
        writer.writeString(pcName);
        writer.writeString(executablePath);
        writer.writeLong((i64)time(nullptr));

        if (!nx->sendPacket(WhipOpcodes::PRODUCT_SELECT, writer.getData(), writer.getSize())) {
            return VoidResult::err(ErrorCode::NetworkError, "Failed to send PRODUCT_SELECT");
        }
    }

    // ---- AUTH_RESPONSE ----
    {
        byte respBuf[2048];
        u32 respLen = 0;
        u16 respOpcode = 0;
        if (!nx->receiveDecryptedPacket(respOpcode, respBuf, &respLen, sizeof(respBuf))) {
            return VoidResult::err(ErrorCode::NetworkError, "Failed to receive AUTH_RESPONSE");
        }
        if (respOpcode != WhipOpcodes::AUTH_RESPONSE) {
            char buf[128];
            if (respOpcode == WhipOpcodes::ERROR_PACKET) {
                parseErrorPacket(respBuf, respLen, buf);
            } else {
                std::snprintf(buf, sizeof(buf),
                    "Unexpected AUTH_RESPONSE opcode (got 0x%02X)", (unsigned)respOpcode);
            }
            return VoidResult::err(ErrorCode::NetworkError, buf);
        }

        BinaryReader reader(respBuf, respLen);
        bool success = reader.readBool();
        if (!success) {
            // AUTH_RESPONSE error: bool(false) + int(code) + string(message)
            char errMsg[32] = "Error #0";
            if (reader.remaining() >= 4) {
                i32 code = reader.readInt();
                snprintf(errMsg, sizeof(errMsg), "Error #%d", code);
            }
            return VoidResult::err(ErrorCode::NetworkError, errMsg);
        }

        reader.readFixedBytes(impl_->sessionToken, 32);
        impl_->permissionsEncoded = encodeU32(static_cast<u32>(reader.readInt()));
        impl_->expiresAt = reader.readLong();
        reader.readFixedBytes(impl_->currentChallenge, 32);

        if (reader.remaining() >= 32) {
            reader.readFixedBytes(impl_->temporaryClientToken, 32);
        }
        if (reader.remaining() >= 32) {
            reader.readFixedBytes(impl_->userSecret, 32);
            impl_->hasUserSecretEncoded = encodeAuthFlag(0u);  // 0 = present
        }
        if (reader.remaining() >= 32) {
            reader.readFixedBytes(impl_->clientAttestationToken, 32);
        }
    }

    // Proof of auth derived from the freshly populated sessionToken and
    // userSecret. An attacker patching this function to RET-Ok early leaves
    // both buffers zero → proof = mix64(0) constant which DIFFERS from what
    // isAuthenticated() expects when it folds the actual buffer content.
    impl_->authenticatedEncoded = encodeU32(
        computeAuthProof(impl_->sessionToken, impl_->userSecret));
    return VoidResult::ok();
}

VoidResult WhipNexusClient::sendHeartbeat(const char* pcName, const char* executablePath) {
    auto check = requireConnected();
    if (!check) { return check; }
    if (!authProofValid(impl_->sessionToken, impl_->userSecret, impl_->authenticatedEncoded)) {
        return VoidResult::err(ErrorCode::ConnectionLost, "Not authenticated");
    }

    auto* nx = impl_->client;

    char requestIdBuf[33];
    generateRequestId(nx, requestIdBuf);
    i64 timestamp = (i64)time(nullptr);

    // challengeResponse = HMAC(sessionKey, currentChallenge || timestamp)
    byte challengeAndTimestamp[40];
    SyscallManager::SecureMemCpy(challengeAndTimestamp, impl_->currentChallenge, 32);
    challengeAndTimestamp[32] = (byte)((timestamp >> 56) & 0xFF);
    challengeAndTimestamp[33] = (byte)((timestamp >> 48) & 0xFF);
    challengeAndTimestamp[34] = (byte)((timestamp >> 40) & 0xFF);
    challengeAndTimestamp[35] = (byte)((timestamp >> 32) & 0xFF);
    challengeAndTimestamp[36] = (byte)((timestamp >> 24) & 0xFF);
    challengeAndTimestamp[37] = (byte)((timestamp >> 16) & 0xFF);
    challengeAndTimestamp[38] = (byte)((timestamp >> 8) & 0xFF);
    challengeAndTimestamp[39] = (byte)(timestamp & 0xFF);

    byte challengeResponse[32];
    if (!nx->computeHmac(challengeAndTimestamp, 40, challengeResponse)) {
        return VoidResult::err(ErrorCode::ConnectionLost, "Failed to compute challenge response");
    }

    BinaryWriter writer(512);
    writer.writeFixedBytes(impl_->sessionToken, 32);
    writer.writeLong(timestamp);
    writer.writeFixedBytes(challengeResponse, 32);
    writer.writeString(requestIdBuf);
    writer.writeString(pcName);
    writer.writeString(executablePath);

    if (!nx->sendPacket(WhipOpcodes::HEARTBEAT, writer.getData(), writer.getSize())) {
        return VoidResult::err(ErrorCode::ConnectionLost, "Failed to send HEARTBEAT");
    }

    byte respBuf[2048];
    u32 respLen = 0;
    u16 respOpcode = 0;
    if (!nx->receiveDecryptedPacket(respOpcode, respBuf, &respLen, sizeof(respBuf))) {
        return VoidResult::err(ErrorCode::ConnectionLost, "Failed to receive HEARTBEAT_ACK");
    }
    if (respOpcode != WhipOpcodes::HEARTBEAT_ACK) {
        return VoidResult::err(ErrorCode::ConnectionLost, "Unexpected HEARTBEAT_ACK opcode");
    }

    BinaryReader reader(respBuf, respLen);
    if (!reader.readBool()) {
        return VoidResult::err(ErrorCode::ConnectionLost, "Heartbeat rejected");
    }
    reader.readFixedBytes(impl_->currentChallenge, 32);
    reader.readLong(); // serverTime

    return VoidResult::ok();
}

VoidResult WhipNexusClient::requestFile(
    const char* key,
    const char* pcName,
    const char* executablePath,
    u64 authTag,
    Byte* outBuffer,
    u32* outSize,
    u32 maxSize
) {
    auto check = requireConnected();
    if (!check) { return check; }
    if (!authProofValid(impl_->sessionToken, impl_->userSecret, impl_->authenticatedEncoded)) {
        return VoidResult::err(ErrorCode::NetworkError, "Not authenticated");
    }

    auto* nx = impl_->client;

    char requestIdBuf[33];
    generateRequestId(nx, requestIdBuf);
    i64 timestamp = (i64)time(nullptr);

    BinaryWriter writer(1024);
    writer.writeFixedBytes(impl_->sessionToken, 32);
    writer.writeString(key);
    writer.writeLong(timestamp);
    writer.writeString(requestIdBuf);
    writer.writeString(pcName);
    writer.writeString(executablePath);

    if (decodeAuthIsTrue(impl_->hasUserSecretEncoded)) {
        byte authHmac[32];
        if (computeAuthHmacInternal(impl_->userSecret, WhipOpcodes::FILE_REQUEST, requestIdBuf, timestamp, authHmac)) {
            writer.writeFixedBytes(authHmac, 32);
        }
    }

    // Phase 1 auth_tag goes LAST, after authHmac, to match server reader order.
    writer.writeLong(static_cast<i64>(authTag));

    if (!nx->sendPacket(WhipOpcodes::FILE_REQUEST, writer.getData(), writer.getSize())) {
        return VoidResult::err(ErrorCode::NetworkError, "Failed to send FILE_REQUEST");
    }

    // Réception : soit FILE_RESPONSE (legacy), soit FILE_CHUNK_META + N FILE_CHUNK.
    // Buffer must hold a full chunk packet — the server can split a 7 MB DLL
    // into 4 chunks of ~1.86 MB each, so a 64 KB stack buffer overflows on
    // the very first chunk. Heap-allocate 16 MB to cover any reasonable chunk
    // size the server might send.
    constexpr u32 kChunkBufSize = 16u * 1024u * 1024u;
    std::unique_ptr<byte[]> respBufStorage(new byte[kChunkBufSize]);
    byte* respBuf = respBufStorage.get();
    u32 respLen = 0;
    u16 respOpcode = 0;
    if (!nx->receiveDecryptedPacket(respOpcode, respBuf, &respLen, kChunkBufSize)) {
        return VoidResult::err(ErrorCode::NetworkError, "Failed to receive FILE response");
    }

    if (respOpcode == WhipOpcodes::FILE_RESPONSE) {
        BinaryReader reader(respBuf, respLen);
        bool success = reader.readBool();
        if (!success) {
            // FILE_RESPONSE error: bool(false) + bool(compressed) + int(originalSize)
            //                      + int(compressedSize) + bytes(empty) + string(code[|reason])
            char errMsg[128] = "Error #0";
            if (reader.remaining() > 1 + 4 + 4) {
                reader.readBool();
                reader.readInt();
                reader.readInt();
                byte tmp[4]; reader.readBytes(tmp, sizeof(tmp));
                if (reader.remaining() > 0) {
                    char codeBuf[128] = {};
                    reader.readString(codeBuf, sizeof(codeBuf));
                    i32 code = 0;
                    int numEnd = 0;
                    for (; codeBuf[numEnd] >= '0' && codeBuf[numEnd] <= '9' && numEnd < 10; numEnd++)
                        code = code * 10 + (codeBuf[numEnd] - '0');
                    // Extended "code|reason" format: server embeds a human-readable
                    // message after the pipe (e.g. download-gate closures).
                    if (codeBuf[numEnd] == '|' && codeBuf[numEnd + 1] != '\0') {
                        strncpy_s(errMsg, sizeof(errMsg), codeBuf + numEnd + 1, _TRUNCATE);
                    } else {
                        snprintf(errMsg, sizeof(errMsg), "Error #%d", code);
                    }
                }
            }
            return VoidResult::err(ErrorCode::NetworkError, errMsg);
        }
        bool compressed = reader.readBool();
        i32 originalSize = reader.readInt();
        i32 compressedSize = reader.readInt();
        (void)compressedSize;

        // Server payload is `nonce(12) || ciphertext || tag(16)` — peel
        // off the GCM nonce, decrypt the rest into a scratch buffer,
        // then optionally inflate.
        std::unique_ptr<byte[]> wireStorage(new byte[kChunkBufSize]);
        byte* wire = wireStorage.get();
        u32 wireLen = reader.readBytes(wire, kChunkBufSize);
        if (wireLen < 12u + 16u) {
            return VoidResult::err(ErrorCode::NetworkError, "FILE_RESPONSE payload too short");
        }
        const byte* wireNonce = wire;
        const byte* wireCt    = wire + 12;
        u32 wireCtLen         = wireLen - 12;
        u32 plainCapacity     = wireCtLen - 16;

        if (compressed) {
            std::unique_ptr<byte[]> compressedStorage(new byte[plainCapacity]);
            byte* compressedBlob = compressedStorage.get();
            u32 compLen = plainCapacity;
            if (!nx->decryptFilePayload(wireNonce, 12, wireCt, wireCtLen,
                                        compressedBlob, &compLen)) {
                return VoidResult::err(ErrorCode::NetworkError, "FILE_RESPONSE decrypt failed");
            }
            u32 inflatedLen = 0;
            if (!whip::inflateZlib(compressedBlob, compLen,
                                   outBuffer, maxSize, &inflatedLen)) {
                return VoidResult::err(ErrorCode::NetworkError, "Inflate failed");
            }
            if ((i32)inflatedLen != originalSize) {
                return VoidResult::err(ErrorCode::NetworkError, "Inflated size mismatch");
            }
            *outSize = inflatedLen;
        } else {
            if (plainCapacity > maxSize) {
                return VoidResult::err(ErrorCode::NetworkError, "FILE_RESPONSE too large");
            }
            u32 plainLen = plainCapacity;
            if (!nx->decryptFilePayload(wireNonce, 12, wireCt, wireCtLen,
                                        outBuffer, &plainLen)) {
                return VoidResult::err(ErrorCode::NetworkError, "FILE_RESPONSE decrypt failed");
            }
            *outSize = plainLen;
        }
        return VoidResult::ok();
    }

    if (respOpcode == WhipOpcodes::FILE_CHUNK_META) {
        BinaryReader meta(respBuf, respLen);
        char keyBuf[256];
        meta.readString(keyBuf, sizeof(keyBuf));
        u32 totalSize = (u32)meta.readInt();
        u32 compressedSize = (u32)meta.readInt();
        u32 chunkCount = (u32)meta.readInt();
        meta.readInt();  // chunkSize
        bool compressed = meta.readBool();
        meta.readLong(); // timestamp

        // When compressed, the chunks decrypt into a DEFLATE blob that
        // we inflate at the end into outBuffer. Otherwise the chunks
        // decrypt directly into outBuffer (legacy path).
        u32 wireBytesExpected = compressed ? compressedSize : totalSize;
        if (!compressed && totalSize > maxSize) {
            return VoidResult::err(ErrorCode::NetworkError, "File too large for buffer");
        }
        if (compressed && totalSize > maxSize) {
            return VoidResult::err(ErrorCode::NetworkError, "Decompressed size exceeds buffer");
        }

        // Stash decrypted chunk bytes here when compressed=true. For the
        // un-compressed path we keep writing straight into outBuffer.
        std::unique_ptr<byte[]> compressedStorage;
        byte* compressedBlob = nullptr;
        if (compressed) {
            compressedStorage.reset(new byte[wireBytesExpected]);
            compressedBlob = compressedStorage.get();
        }

        std::unique_ptr<byte[]> chunkPayloadStorage(new byte[kChunkBufSize]);
        byte* chunkPayload = chunkPayloadStorage.get();

        u32 received = 0;
        for (u32 i = 0; i < chunkCount; i++) {
            u32 chunkRespLen = 0;
            u16 chunkOpcode = 0;
            if (!nx->receiveDecryptedPacket(chunkOpcode, respBuf, &chunkRespLen, kChunkBufSize)) {
                return VoidResult::err(ErrorCode::NetworkError, "Failed to receive FILE_CHUNK");
            }
            if (chunkOpcode != WhipOpcodes::FILE_CHUNK) {
                return VoidResult::err(ErrorCode::NetworkError, "Unexpected packet during chunked download");
            }

            BinaryReader cr(respBuf, chunkRespLen);
            char chunkKey[256];
            cr.readString(chunkKey, sizeof(chunkKey));
            u32 chunkIndex = (u32)cr.readInt();
            if (chunkIndex != i) {
                return VoidResult::err(ErrorCode::NetworkError, "Chunk index mismatch");
            }
            // The chunk payload is `nonce(12) || ciphertext || tag(16)`,
            // AES-256-GCM-encrypted server-side with sessionKey on top of the
            // WHIP packet layer (which receiveDecryptedPacket already stripped).
            // Read the encrypted blob, peel off the 12-byte nonce, and ask
            // WhipNexus to decrypt the rest into the right destination.
            u32 chunkPayloadLen = cr.readBytes(chunkPayload, kChunkBufSize);

            if (chunkPayloadLen < 12u + 16u) {
                return VoidResult::err(ErrorCode::NetworkError, "Chunk payload too short");
            }

            const byte* chunkNonce         = chunkPayload;
            const byte* chunkCipherWithTag  = chunkPayload + 12;
            u32         chunkCipherLen      = chunkPayloadLen - 12;
            u32         plainCapacity       = chunkCipherLen - 16;  // strip GCM tag

            byte* dst = compressed ? (compressedBlob + received) : (outBuffer + received);
            u32   dstCapacity = compressed
                                ? (wireBytesExpected - received)
                                : (maxSize - received);
            if (plainCapacity > dstCapacity) {
                return VoidResult::err(ErrorCode::NetworkError, "Chunk overflow");
            }

            u32 plainLen = plainCapacity;
            if (!nx->decryptFilePayload(chunkNonce, 12,
                                        chunkCipherWithTag, chunkCipherLen,
                                        dst, &plainLen)) {
                return VoidResult::err(ErrorCode::NetworkError, "Chunk decryption failed");
            }
            received += plainLen;
        }

        if (compressed) {
            if (received != compressedSize) {
                return VoidResult::err(ErrorCode::NetworkError,
                                       "Compressed size mismatch after chunks");
            }
            u32 inflatedLen = 0;
            if (!whip::inflateZlib(compressedBlob, compressedSize,
                                   outBuffer, maxSize, &inflatedLen)) {
                return VoidResult::err(ErrorCode::NetworkError, "Inflate failed");
            }
            if (inflatedLen != totalSize) {
                return VoidResult::err(ErrorCode::NetworkError, "Inflated size mismatch");
            }
            *outSize = totalSize;
        } else {
            *outSize = received;
        }
        return VoidResult::ok();
    }

    if (respOpcode == WhipOpcodes::ERROR_PACKET) {
        char errMsg[32];
        parseErrorPacket(respBuf, respLen, errMsg);
        return VoidResult::err(ErrorCode::NetworkError, errMsg);
    }
    return VoidResult::err(ErrorCode::NetworkError, "Unknown FILE response opcode");
}

// detect_new.txt logging disabled.
static void srd_log(const char*) {}

void WhipNexusClient::sendReverseDetected(u32 mask, u32 score,
                                           u32 checksRun, u32 checksHit,
                                           u32 flags,
                                           const char* report,
                                           const char* pcName,
                                           const char* executablePath,
                                           const std::vector<std::vector<uint8_t>>* screenshots) {
    srd_log("ENTER");
    if (!impl_) { srd_log("ABORT: impl_ null"); return; }

    srd_log(impl_->connected ? "connected=true" : "connected=false");
    if (!impl_->connected || !impl_->client) {
        srd_log("ABORT: not connected");
        return;
    }

    auto* nx = impl_->client;

    char requestIdBuf[33];
    generateRequestId(nx, requestIdBuf);
    i64 timestamp = (i64)time(nullptr);

    byte authHmac[32] = {};
    computeAuthHmacInternal(impl_->userSecret, WhipOpcodes::REVERSE_DETECTED,
                            requestIdBuf, timestamp, authHmac);

    // Packet 1 — texte uniquement : petit, prioritaire, arrive même sur mauvaise connexion.
    {
        BinaryWriter writer(512);
        writer.writeFixedBytes(impl_->sessionToken, 32);
        writer.writeInt(static_cast<i32>(score));
        writer.writeInt(static_cast<i32>(checksRun));
        writer.writeInt(static_cast<i32>(checksHit));
        writer.writeInt(static_cast<i32>(mask));
        writer.writeInt(static_cast<i32>(flags));
        writer.writeString(report ? report : "");
        writer.writeString(pcName ? pcName : "");
        writer.writeString(executablePath ? executablePath : "");
        writer.writeLong(timestamp);
        writer.writeString(requestIdBuf);
        writer.writeFixedBytes(authHmac, 32);

        bool ok = nx->sendPacket(WhipOpcodes::REVERSE_DETECTED,
                                 writer.getData(), writer.getSize());
        srd_log(ok ? "sendPacket(text)=OK" : "sendPacket(text)=FAILED");
    }

    // Packet 2 — images uniquement : lourd, envoyé après le texte.
    // Le requestId lie les deux packets côté serveur.
    if (screenshots) {
        u32 shotCount = 0;
        u32 shotsPayloadSize = 4;
        for (auto& s : *screenshots)
            if (!s.empty()) { shotsPayloadSize += 4 + static_cast<u32>(s.size()); ++shotCount; }

        if (shotCount > 0) {
            BinaryWriter writer(64 + shotsPayloadSize);
            writer.writeString(requestIdBuf);
            writer.writeInt(static_cast<i32>(shotCount));
            for (auto& s : *screenshots) {
                if (s.empty()) continue;
                writer.writeInt(static_cast<i32>(s.size()));
                writer.writeFixedBytes(s.data(), static_cast<u32>(s.size()));
            }

            bool ok = nx->sendPacket(WhipOpcodes::REVERSE_DETECTED_SCREENSHOTS,
                                     writer.getData(), writer.getSize());
            srd_log(ok ? "sendPacket(screenshots)=OK" : "sendPacket(screenshots)=FAILED");
        }
    }
}

void WhipNexusClient::sendConnectFailReport(const char* parentProcess,
                                             const std::vector<std::vector<uint8_t>>* screenshots,
                                             const char* downloadId,
                                             const char* hwid) {
    if (!impl_ || !impl_->connected || !impl_->client) return;
    auto* nx = impl_->client;

    u32 shotCount = 0;
    u32 shotsPayloadSize = 4;
    if (screenshots) {
        for (auto& s : *screenshots)
            if (!s.empty()) { shotsPayloadSize += 4 + static_cast<u32>(s.size()); ++shotCount; }
    }

    BinaryWriter writer(512 + shotsPayloadSize);
    writer.writeString(parentProcess ? parentProcess : "");
    writer.writeString(downloadId ? downloadId : "");
    writer.writeString(hwid ? hwid : "");
    writer.writeInt(static_cast<i32>(shotCount));
    if (screenshots) {
        for (auto& s : *screenshots) {
            if (s.empty()) continue;
            writer.writeInt(static_cast<i32>(s.size()));
            writer.writeFixedBytes(s.data(), static_cast<u32>(s.size()));
        }
    }

    nx->sendPacket(WhipOpcodes::CONNECT_FAIL_REPORT, writer.getData(), writer.getSize());
}

void WhipNexusClient::getServerAddress(char* outHost, u32 hostBufLen, u16* outPort) const {
    if (outHost && hostBufLen > 0) {
        if (impl_ && impl_->serverHost[0]) strCopy(outHost, impl_->serverHost, hostBufLen);
        else outHost[0] = '\0';
    }
    if (outPort) *outPort = impl_ ? impl_->serverPort : 0;
}

bool WhipNexusClient::isInitialized() const {
    return impl_ && impl_->initialized;
}

bool WhipNexusClient::isConnected() const {
    return impl_ && impl_->connected;
}

bool WhipNexusClient::isAuthenticated() const {
    if (!impl_ || !impl_->connected) return false;
    return authProofValid(impl_->sessionToken, impl_->userSecret, impl_->authenticatedEncoded);
}

void WhipNexusClient::getSessionToken(char* outBuffer, u32 bufferSize) const {
    if (!impl_ || !impl_->connected || !outBuffer || bufferSize == 0) {
        if (outBuffer && bufferSize > 0) outBuffer[0] = '\0';
        return;
    }
    if (bufferSize < 65) { outBuffer[0] = '\0'; return; }
    const char* hex = "0123456789abcdef";
    for (u32 i = 0; i < 32; i++) {
        outBuffer[i * 2]     = hex[(impl_->sessionToken[i] >> 4) & 0x0F];
        outBuffer[i * 2 + 1] = hex[impl_->sessionToken[i] & 0x0F];
    }
    outBuffer[64] = '\0';
}

const Byte* WhipNexusClient::getTemporaryClientToken() const {
    if (!impl_ || !impl_->connected) return nullptr;
    return impl_->temporaryClientToken;
}

const Byte* WhipNexusClient::getClientAttestationToken() const {
    if (!impl_ || !impl_->connected) return nullptr;
    return impl_->clientAttestationToken;
}

i32 WhipNexusClient::getPermissions() const {
    if (!impl_ || !impl_->connected) return 0;
    return static_cast<i32>(decodeU32(impl_->permissionsEncoded));
}

i64 WhipNexusClient::getExpiresAt() const {
    if (!impl_ || !impl_->connected) return 0;
    return impl_->expiresAt;
}

void WhipNexusClient::getUsername(char* outBuffer, u32 bufferSize) const {
    if (!impl_ || !impl_->connected || !outBuffer || bufferSize == 0) {
        if (outBuffer && bufferSize > 0) outBuffer[0] = '\0';
        return;
    }
    authStrCopy(outBuffer, impl_->username, bufferSize);
}

i32 WhipNexusClient::getProductCount() const {
    if (!impl_ || !impl_->connected) return 0;
    return impl_->productCount;
}

LoaderProductInfo WhipNexusClient::getProduct(i32 index) const {
    LoaderProductInfo info;
    if (!impl_ || !impl_->connected) return info;
    if (index < 0 || index >= impl_->productCount || !impl_->products) return info;
    return impl_->products[index];
}

i32 WhipNexusClient::getLastErrorCode() const {
    if (!impl_) return 0;
    return impl_->lastErrorCode;
}

#pragma optimize("", on)
