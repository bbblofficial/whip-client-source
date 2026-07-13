#pragma optimize("", off)
#include "whipnexus/PacketCodec.h"
#include "whipnexus/SyscallManager.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

PacketCodec::PacketCodec(CryptoService* cryptoService) : crypto(cryptoService) {
    VMProtectBeginMutation("PacketCodec_ctor");
    VMProtectEnd();
}

bool PacketCodec::encodeRawPacket(const RawPacket& packet, Buffer& output) {
    VMProtectBeginMutation("PacketCodec_encodeRawPacket");
    u32 totalSize = ProtocolConstants::HEADER_SIZE + packet.payload.size + ProtocolConstants::HMAC_SIZE;
    output.resize(totalSize);

    byte* ptr = output.data;

    // Magic (4 bytes)
    SyscallManager::SecureMemCpy(ptr, ProtocolConstants::MAGIC, 4);
    ptr += 4;

    // Version (2 bytes, big-endian)
    u16 version = ProtocolConstants::VERSION;
    ptr[0] = (byte)((version >> 8) & 0xFF);
    ptr[1] = (byte)(version & 0xFF);
    ptr += 2;

    // Opcode (2 bytes, big-endian) — neutre, fourni par l'appelant
    u16 typeId = packet.opcode;
    ptr[0] = (byte)((typeId >> 8) & 0xFF);
    ptr[1] = (byte)(typeId & 0xFF);
    ptr += 2;

    // Payload length (4 bytes, big-endian)
    u32 payloadLen = packet.payload.size;
    ptr[0] = (byte)((payloadLen >> 24) & 0xFF);
    ptr[1] = (byte)((payloadLen >> 16) & 0xFF);
    ptr[2] = (byte)((payloadLen >> 8) & 0xFF);
    ptr[3] = (byte)(payloadLen & 0xFF);
    ptr += 4;

    // Nonce (12 bytes)
    SyscallManager::SecureMemCpy(ptr, packet.nonce, ProtocolConstants::NONCE_SIZE);
    ptr += ProtocolConstants::NONCE_SIZE;

    // Payload
    if (packet.payload.size > 0) {
        SyscallManager::SecureMemCpy(ptr, packet.payload.data, packet.payload.size);
        ptr += packet.payload.size;
    }

    // HMAC (32 bytes)
    SyscallManager::SecureMemCpy(ptr, packet.hmac, ProtocolConstants::HMAC_SIZE);

    return true;
    VMProtectEnd();
}

bool PacketCodec::decodeRawPacket(const byte* data, u32 length, RawPacket& packet) {
    VMProtectBeginMutation("PacketCodec_decodeRawPacket");
    if (length < ProtocolConstants::HEADER_SIZE + ProtocolConstants::HMAC_SIZE) {
        return false;
    }

    const byte* ptr = data;

    if (SyscallManager::SecureMemCmp(ptr, ProtocolConstants::MAGIC, 4) != 0) {
        return false;
    }
    ptr += 4;

    u16 version = ((u16)ptr[0] << 8) | ((u16)ptr[1]);
    if (version != ProtocolConstants::VERSION) {
        return false;
    }
    ptr += 2;

    u16 typeId = ((u16)ptr[0] << 8) | ((u16)ptr[1]);
    packet.opcode = typeId;
    ptr += 2;

    u32 payloadLen = ((u32)ptr[0] << 24) | ((u32)ptr[1] << 16) |
                     ((u32)ptr[2] << 8) | ((u32)ptr[3]);
    ptr += 4;

    if (payloadLen > ProtocolConstants::MAX_PAYLOAD_SIZE) {
        return false;
    }

    u32 expectedTotal = ProtocolConstants::HEADER_SIZE + payloadLen + ProtocolConstants::HMAC_SIZE;
    if (length < expectedTotal) {
        return false;
    }

    SyscallManager::SecureMemCpy(packet.nonce, ptr, ProtocolConstants::NONCE_SIZE);
    ptr += ProtocolConstants::NONCE_SIZE;

    packet.payload.resize(payloadLen);
    if (payloadLen > 0) {
        SyscallManager::SecureMemCpy(packet.payload.data, ptr, payloadLen);
        ptr += payloadLen;
    }

    SyscallManager::SecureMemCpy(packet.hmac, ptr, ProtocolConstants::HMAC_SIZE);

    return true;
    VMProtectEnd();
}

bool PacketCodec::encodeClientHello(const ClientHelloData& data, Buffer& payload) {
    VMProtectBeginMutation("PacketCodec_encodeClientHello");
    BinaryWriter writer(512);

    writer.writeInt(data.version);
    writer.writeFixedBytes(data.clientNonce, ProtocolConstants::CLIENT_NONCE_SIZE);
    writer.writeLengthPrefixedBytes(data.clientPublicKey, data.clientPublicKeyLength);

    payload.resize(writer.getSize());
    SyscallManager::SecureMemCpy(payload.data, writer.getData(), writer.getSize());

    return true;
    VMProtectEnd();
}

bool PacketCodec::decodeClientHello(const byte* payload, u32 length, ClientHelloData& data) {
    VMProtectBeginMutation("PacketCodec_decodeClientHello");
    BinaryReader reader(payload, length);

    data.version = reader.readInt();
    reader.readFixedBytes(data.clientNonce, ProtocolConstants::CLIENT_NONCE_SIZE);

    byte tempKey[512];
    u32 keyLen = reader.readBytes(tempKey, sizeof(tempKey));

    if (keyLen > 0) {
        data.clientPublicKey = (byte*)SyscallManager::GetWrappers()->HeapAlloc(keyLen);
        SyscallManager::SecureMemCpy(data.clientPublicKey, tempKey, keyLen);
        data.clientPublicKeyLength = keyLen;
    } else {
        data.clientPublicKey = nullptr;
        data.clientPublicKeyLength = 0;
    }

    return true;
    VMProtectEnd();
}

bool PacketCodec::encodeServerHello(const ServerHelloData& data, Buffer& payload) {
    VMProtectBeginMutation("PacketCodec_encodeServerHello");
    BinaryWriter writer(1024);

    writer.writeFixedBytes(data.serverNonce, 32);
    writer.writeString(data.tempSessionId);
    writer.writeLengthPrefixedBytes(data.serverPublicKey, data.serverPublicKeyLength);
    writer.writeLengthPrefixedBytes(data.serverPermanentPublicKey, data.serverPermanentPublicKeyLength);
    writer.writeLengthPrefixedBytes(data.signature, data.signatureLength);

    payload.resize(writer.getSize());
    SyscallManager::SecureMemCpy(payload.data, writer.getData(), writer.getSize());

    return true;
    VMProtectEnd();
}

bool PacketCodec::decodeServerHello(const byte* payload, u32 length, ServerHelloData& data) {
    VMProtectBeginMutation("PacketCodec_decodeServerHello");
    BinaryReader reader(payload, length);

    reader.readFixedBytes(data.serverNonce, 32);
    reader.readString(data.tempSessionId, sizeof(data.tempSessionId));

    byte tempKey[512];
    u32 keyLen = reader.readBytes(tempKey, sizeof(tempKey));

    if (keyLen > 0) {
        data.serverPublicKey = (byte*)SyscallManager::GetWrappers()->HeapAlloc(keyLen);
        SyscallManager::SecureMemCpy(data.serverPublicKey, tempKey, keyLen);
        data.serverPublicKeyLength = keyLen;
    } else {
        data.serverPublicKey = nullptr;
        data.serverPublicKeyLength = 0;
    }

    byte tempPermKey[512];
    u32 permKeyLen = reader.readBytes(tempPermKey, sizeof(tempPermKey));

    if (permKeyLen > 0) {
        data.serverPermanentPublicKey = (byte*)SyscallManager::GetWrappers()->HeapAlloc(permKeyLen);
        SyscallManager::SecureMemCpy(data.serverPermanentPublicKey, tempPermKey, permKeyLen);
        data.serverPermanentPublicKeyLength = permKeyLen;
    } else {
        data.serverPermanentPublicKey = nullptr;
        data.serverPermanentPublicKeyLength = 0;
    }

    byte tempSig[512];
    u32 sigLen = reader.readBytes(tempSig, sizeof(tempSig));

    if (sigLen > 0) {
        data.signature = (byte*)SyscallManager::GetWrappers()->HeapAlloc(sigLen);
        SyscallManager::SecureMemCpy(data.signature, tempSig, sigLen);
        data.signatureLength = sigLen;
    } else {
        data.signature = nullptr;
        data.signatureLength = 0;
    }

    return true;
    VMProtectEnd();
}

bool PacketCodec::createEncryptedPacket(u16 opcode, const Buffer& plainPayload,
                                         const byte* sessionKey, RawPacket& packet) {
    VMProtectBeginMutation("PacketCodec_createEncryptedPacket");

    packet.opcode = opcode;

    if (!crypto->generateNonce(packet.nonce)) {
        return false;
    }

    byte paddingLenByte;
    crypto->generateRandomBytes(&paddingLenByte, 1);
    u32 paddingSize = ProtocolConstants::MIN_PADDING_SIZE +
        (paddingLenByte % (ProtocolConstants::MAX_PADDING_SIZE - ProtocolConstants::MIN_PADDING_SIZE + 1));

    u32 paddedSize = plainPayload.size + paddingSize;
    Buffer paddedPayload(paddedSize);
    SyscallManager::SecureMemCpy(paddedPayload.data, plainPayload.data, plainPayload.size);
    crypto->generateRandomBytes(paddedPayload.data + plainPayload.size, paddingSize);
    paddedPayload.size = paddedSize;

    u32 maxCiphertextLen = paddedSize + 16;
    packet.payload.resize(maxCiphertextLen);

    u32 actualCiphertextLen = 0;
    if (!crypto->encrypt(paddedPayload.data, paddedPayload.size,
                         sessionKey, 32,
                         packet.nonce, ProtocolConstants::NONCE_SIZE,
                         packet.payload.data, &actualCiphertextLen)) {
        return false;
    }

    packet.payload.size = actualCiphertextLen;

    if (!crypto->hmacSha256(packet.payload.data, packet.payload.size,
                            sessionKey, 32,
                            packet.hmac)) {
        return false;
    }

    return true;
    VMProtectEnd();
}

bool PacketCodec::decryptPacket(const RawPacket& packet, const byte* sessionKey, Buffer& plainPayload) {
    VMProtectBeginMutation("PacketCodec_decryptPacket");

    if (!crypto->verifyHmac(packet.payload.data, packet.payload.size,
                            sessionKey, 32,
                            packet.hmac)) {
        return false;
    }

    u32 maxPlaintextLen = packet.payload.size;
    plainPayload.resize(maxPlaintextLen);

    u32 actualPlaintextLen = 0;
    if (!crypto->decrypt(packet.payload.data, packet.payload.size,
                         sessionKey, 32,
                         packet.nonce, ProtocolConstants::NONCE_SIZE,
                         plainPayload.data, &actualPlaintextLen)) {
        return false;
    }

    plainPayload.size = actualPlaintextLen;
    return true;
    VMProtectEnd();
}
