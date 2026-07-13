#pragma optimize("", off)
#include "whipnexus/TlsServerContext.h"
#include "whipnexus/X509CertBuilder.h"
#include "whipnexus/SyscallManager.h"
#include "whipsyscall/AfdSocket.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif


__forceinline void TlsServerContext::putU16BE(byte* dst, u16 val) {
    dst[0] = (byte)(val >> 8);
    dst[1] = (byte)(val);
}
__forceinline void TlsServerContext::putU24BE(byte* dst, u32 val) {
    dst[0] = (byte)(val >> 16);
    dst[1] = (byte)(val >> 8);
    dst[2] = (byte)(val);
}
__forceinline void TlsServerContext::putU64BE(byte* dst, u64 val) {
    for (int i = 7; i >= 0; i--) {
        dst[7 - i] = (byte)(val >> (i * 8));
    }
}
__forceinline u16 TlsServerContext::getU16BE(const byte* src) {
    return ((u16)src[0] << 8) | src[1];
}
__forceinline u32 TlsServerContext::getU24BE(const byte* src) {
    return ((u32)src[0] << 16) | ((u32)src[1] << 8) | src[2];
}

TlsServerContext::TlsServerContext()
    : rawSocket(nullptr), resolver(nullptr), crypto(nullptr),
      hAesGcm(nullptr), hSha256(nullptr), hHmacSha256(nullptr),
      clientSeqNum(0), serverSeqNum(0),
      handshakeHashObj(nullptr), hHandshakeHash(nullptr),
      tlsEstablished(false), cipherActive(false), clientCipherActive(false),
      recvBufStart(0), recvBufLen(0),
      serverCertDer(nullptr), serverCertDerLen(0), ecdsaPrivateKey(nullptr) {
    SyscallManager::SecureZero(clientRandom, 32);
    SyscallManager::SecureZero(serverRandom, 32);
    SyscallManager::SecureZero(masterSecret, 48);
    SyscallManager::SecureZero(clientWriteKey, 16);
    SyscallManager::SecureZero(serverWriteKey, 16);
    SyscallManager::SecureZero(clientWriteIV, 4);
    SyscallManager::SecureZero(serverWriteIV, 4);
}

TlsServerContext::~TlsServerContext() {
    shutdown();
    cleanupAlgorithms();
}

void TlsServerContext::init(HANDLE socket, SyscallResolver* res, CryptoService* cryptoSvc,
                             const byte* certDer, u32 certDerLen, void* ecdsaPrivKey) {
    rawSocket = socket;
    resolver = res;
    crypto = cryptoSvc;
    serverCertDer = certDer;
    serverCertDerLen = certDerLen;
    ecdsaPrivateKey = ecdsaPrivKey;
}

void TlsServerContext::shutdown() {
    if (tlsEstablished) {
        byte alert[2] = { 1, 0 }; // warning, close_notify
        sendRecord(TLS_CONTENT_ALERT, alert, 2);
    }
    tlsEstablished = false;
    cipherActive = false;
    clientCipherActive = false;
    recvBufStart = 0;
    recvBufLen = 0;
    clientSeqNum = 0;
    serverSeqNum = 0;
    SyscallManager::SecureZero(masterSecret, 48);
    SyscallManager::SecureZero(clientWriteKey, 16);
    SyscallManager::SecureZero(serverWriteKey, 16);
}

// ── BCrypt algorithm handles ────────────────────────────────────────────────
bool TlsServerContext::initAlgorithms() {
    NTSTATUS s;

    s = BCryptOpenAlgorithmProvider(&hAesGcm, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(s)) return false;
    s = BCryptSetProperty(hAesGcm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(s)) return false;

    s = BCryptOpenAlgorithmProvider(&hSha256, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(s)) return false;

    s = BCryptOpenAlgorithmProvider(&hHmacSha256, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(s)) return false;

    return true;
}

void TlsServerContext::cleanupAlgorithms() {
    if (hHandshakeHash) { BCryptDestroyHash(hHandshakeHash); hHandshakeHash = nullptr; }
    if (handshakeHashObj) { delete[] handshakeHashObj; handshakeHashObj = nullptr; }
    if (hAesGcm) { BCryptCloseAlgorithmProvider(hAesGcm, 0); hAesGcm = nullptr; }
    if (hSha256) { BCryptCloseAlgorithmProvider(hSha256, 0); hSha256 = nullptr; }
    if (hHmacSha256) { BCryptCloseAlgorithmProvider(hHmacSha256, 0); hHmacSha256 = nullptr; }
}

// ── Raw I/O via AfdSocket ───────────────────────────────────────────────────
bool TlsServerContext::rawSend(const byte* data, u32 len) {
    VMProtectBeginMutation("TlsServerContext_rawSend");
    u32 totalSent = 0;
    while (totalSent < len) {
        ULONG sent = 0;
        if (!AfdSocket::Send(resolver, rawSocket,
                             data + totalSent, len - totalSent, sent)) {
            return false;
        }
        totalSent += sent;
    }
    return true;
    VMProtectEnd();
}

bool TlsServerContext::rawRecvExact(byte* buf, u32 len) {
    VMProtectBeginMutation("TlsServerContext_rawRecvExact");
    u32 totalRecv = 0;
    while (totalRecv < len) {
        ULONG received = 0;
        if (!AfdSocket::Recv(resolver, rawSocket,
                             buf + totalRecv, len - totalRecv, received)
            || received == 0) {
            return false;
        }
        totalRecv += received;
    }
    return true;
    VMProtectEnd();
}

// ── Send (application data over TLS) ────────────────────────────────────────
bool TlsServerContext::send(const byte* data, u32 length) {
    VMProtectBeginMutation("TlsServerContext_send");
    if (!tlsEstablished) return false;

    u32 offset = 0;
    while (offset < length) {
        u32 chunkLen = length - offset;
        if (chunkLen > 16384) chunkLen = 16384;
        if (!sendRecord(TLS_CONTENT_APPLICATION, data + offset, chunkLen)) {
            return false;
        }
        offset += chunkLen;
    }
    return true;
    VMProtectEnd();
}

// ── Receive (application data from TLS) ─────────────────────────────────────
i32 TlsServerContext::receive(byte* buffer, u32 bufferSize) {
    VMProtectBeginMutation("TlsServerContext_receive");
    if (!tlsEstablished) return -1;

    // Return buffered data first
    if (recvBufLen > 0) {
        u32 copyLen = recvBufLen < bufferSize ? recvBufLen : bufferSize;
        SyscallManager::SecureMemCpy(buffer, recvBuf + recvBufStart, copyLen);
        recvBufStart += copyLen;
        recvBufLen -= copyLen;
        return (i32)copyLen;
    }

    byte contentType = 0;
    byte recordBuf[16384 + 256];
    u32 recordLen = 0;
    if (!recvRecord(contentType, recordBuf, recordLen, sizeof(recordBuf))) {
        return -1;
    }

    if (contentType == TLS_CONTENT_APPLICATION) {
        u32 copyLen = recordLen < bufferSize ? recordLen : bufferSize;
        SyscallManager::SecureMemCpy(buffer, recordBuf, copyLen);

        if (recordLen > copyLen) {
            u32 remaining = recordLen - copyLen;
            SyscallManager::SecureMemCpy(recvBuf, recordBuf + copyLen, remaining);
            recvBufStart = 0;
            recvBufLen = remaining;
        }
        return (i32)copyLen;
    }

    if (contentType == TLS_CONTENT_ALERT) {
        return -1;
    }

    return -1;
    VMProtectEnd();
}

bool TlsServerContext::receiveExact(byte* buffer, u32 length) {
    VMProtectBeginMutation("TlsServerContext_receiveExact");
    u32 totalRecv = 0;
    while (totalRecv < length) {
        i32 received = receive(buffer + totalRecv, length - totalRecv);
        if (received <= 0) return false;
        totalRecv += (u32)received;
    }
    return true;
    VMProtectEnd();
}

// ── TLS Record Layer ────────────────────────────────────────────────────────
// Server encrypts with serverWriteKey, decrypts with clientWriteKey
// (opposite of TlsSocket client)

bool TlsServerContext::sendRecord(byte contentType, const byte* data, u32 len) {
    VMProtectBeginMutation("TlsServerContext_sendRecord");
    if (cipherActive) {
        // Encrypted record
        byte nonce[12];
        SyscallManager::SecureMemCpy(nonce, serverWriteIV, 4);
        putU64BE(nonce + 4, serverSeqNum);

        byte explicitNonce[8];
        putU64BE(explicitNonce, serverSeqNum);

        // AAD = seq_num(8) || content_type(1) || version(2) || length(2)
        byte aad[13];
        putU64BE(aad, serverSeqNum);
        aad[8] = contentType;
        putU16BE(aad + 9, TLS_VERSION_12);
        putU16BE(aad + 11, (u16)len);

        byte* ciphertext = new byte[len];
        byte tag[16];
        if (!aesGcmEncrypt(serverWriteKey, nonce, aad, 13, data, len, ciphertext, tag)) {
            delete[] ciphertext;
            return false;
        }

        // TLS record: header(5) + explicit_nonce(8) + ciphertext(len) + tag(16)
        u32 recordPayloadLen = 8 + len + 16;
        byte header[5];
        header[0] = contentType;
        putU16BE(header + 1, TLS_VERSION_12);
        putU16BE(header + 3, (u16)recordPayloadLen);

        bool ok = rawSend(header, 5) &&
                  rawSend(explicitNonce, 8) &&
                  rawSend(ciphertext, len) &&
                  rawSend(tag, 16);

        delete[] ciphertext;
        serverSeqNum++;
        return ok;
    } else {
        byte header[5];
        header[0] = contentType;
        putU16BE(header + 1, TLS_VERSION_12);
        putU16BE(header + 3, (u16)len);
        return rawSend(header, 5) && rawSend(data, len);
    }
    VMProtectEnd();
}

bool TlsServerContext::recvRecord(byte& contentType, byte* data, u32& len, u32 maxLen) {
    VMProtectBeginMutation("TlsServerContext_recvRecord");
    byte header[5];
    if (!rawRecvExact(header, 5)) return false;

    contentType = header[0];
    u16 recordLen = getU16BE(header + 3);
    if (recordLen > RAW_BUF_SIZE) return false;

    if (!rawRecvExact(rawRecvBuf, recordLen)) return false;

    if (clientCipherActive &&
        (contentType == TLS_CONTENT_APPLICATION || contentType == TLS_CONTENT_HANDSHAKE)) {
        // Decrypt with clientWriteKey
        if (recordLen < 24) return false; // 8 + 0 + 16 minimum

        byte* explNonce = rawRecvBuf;
        u32 ctLen = recordLen - 8 - 16;
        byte* ct = rawRecvBuf + 8;
        byte* tag = rawRecvBuf + 8 + ctLen;

        byte nonce[12];
        SyscallManager::SecureMemCpy(nonce, clientWriteIV, 4);
        SyscallManager::SecureMemCpy(nonce + 4, explNonce, 8);

        byte aad[13];
        putU64BE(aad, clientSeqNum);
        aad[8] = contentType;
        putU16BE(aad + 9, TLS_VERSION_12);
        putU16BE(aad + 11, (u16)ctLen);

        if (ctLen > maxLen) return false;

        if (!aesGcmDecrypt(clientWriteKey, nonce, aad, 13, ct, ctLen, tag, data)) {
            return false;
        }

        len = ctLen;
        clientSeqNum++;
        return true;
    } else {
        // Plaintext record
        if (recordLen > maxLen) return false;
        SyscallManager::SecureMemCpy(data, rawRecvBuf, recordLen);
        len = recordLen;
        return true;
    }
    VMProtectEnd();
}

bool TlsServerContext::performHandshake() {
    VMProtectBeginMutation("TlsServerContext_performHandshake");

    if (!initAlgorithms()) {
        return false;
    }

    if (!initHandshakeHash()) return false;

    u16 chosenCipher = 0;
    if (!recvClientHello(chosenCipher)) {
        return false;
    }

    byte serverEcdhPub[256];
    u32 serverEcdhPubLen = 0;
    void* serverEcdhPriv = nullptr;
    if (!crypto->generateEcdhKeyPair(serverEcdhPub, &serverEcdhPubLen, &serverEcdhPriv)) {
        return false;
    }

    byte rawPub[65];
    rawPub[0] = 0x04;
    SyscallManager::SecureMemCpy(rawPub + 1, serverEcdhPub + 27, 64);

    if (!sendServerHello(chosenCipher)) {
        crypto->freeKeyHandle(serverEcdhPriv);
        return false;
    }

    if (!sendCertificate()) {
        crypto->freeKeyHandle(serverEcdhPriv);
        return false;
    }

    if (!sendServerKeyExchange(rawPub, 65)) {
        crypto->freeKeyHandle(serverEcdhPriv);
        return false;
    }

    if (!sendServerHelloDone()) {
        crypto->freeKeyHandle(serverEcdhPriv);
        return false;
    }

    byte clientEcdhPub[256];
    u32 clientEcdhPubLen = 0;
    if (!recvClientKeyExchange(clientEcdhPub, clientEcdhPubLen)) {
        crypto->freeKeyHandle(serverEcdhPriv);
        return false;
    }

    byte clientX509[91];
    static const byte x509Header[27] = {
        0x30, 0x59, 0x30, 0x13,
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00, 0x04
    };
    if (clientEcdhPubLen != 65 || clientEcdhPub[0] != 0x04) {
        crypto->freeKeyHandle(serverEcdhPriv);
        return false;
    }
    SyscallManager::SecureMemCpy(clientX509, x509Header, 27);
    SyscallManager::SecureMemCpy(clientX509 + 27, clientEcdhPub + 1, 64);

    byte preMasterSecret[32];
    if (!crypto->deriveRawSecret(serverEcdhPriv, clientX509, 91, preMasterSecret)) {
        crypto->freeKeyHandle(serverEcdhPriv);
        return false;
    }
    crypto->freeKeyHandle(serverEcdhPriv);

    byte seed[64];
    SyscallManager::SecureMemCpy(seed, clientRandom, 32);
    SyscallManager::SecureMemCpy(seed + 32, serverRandom, 32);
    if (!prf(preMasterSecret, 32, "master secret", seed, 64, masterSecret, 48)) {
        return false;
    }
    SyscallManager::SecureZero(preMasterSecret, 32);

    if (!deriveKeys()) return false;

    if (!recvClientChangeCipherSpecAndFinished()) {
        return false;
    }

    if (!sendChangeCipherSpec()) {
        return false;
    }
    if (!sendFinished()) {
        return false;
    }

    tlsEstablished = true;
    return true;
    VMProtectEnd();
}

bool TlsServerContext::recvClientHello(u16& chosenCipher) {
    VMProtectBeginMutation("TlsServerContext_recvClientHello");
    byte contentType = 0;
    byte recordData[16384];
    u32 recordLen = 0;
    if (!recvRecord(contentType, recordData, recordLen, sizeof(recordData))) {
        return false;
    }

    if (contentType != TLS_CONTENT_HANDSHAKE) {
        if (contentType == TLS_CONTENT_ALERT) {
        }
        return false;
    }

    u32 offset = 0;
    while (offset < recordLen) {
        if (offset + 4 > recordLen) return false;

        byte hsType = recordData[offset];
        u32 hsLen = getU24BE(recordData + offset + 1);

        if (offset + 4 + hsLen > recordLen) return false;

        if (hsType == TLS_HS_CLIENT_HELLO) {
            updateHandshakeHash(recordData + offset, 4 + hsLen);

            byte* body = recordData + offset + 4;
            if (hsLen < 38) return false;

            SyscallManager::SecureMemCpy(clientRandom, body + 2, 32);

            u32 p = 34;
            byte sessionIdLen = body[p++];
            p += sessionIdLen;

            if (p + 2 > hsLen) return false;
            u16 cipherSuiteListLen = getU16BE(body + p); p += 2;

            chosenCipher = 0;
            for (u32 i = 0; i < cipherSuiteListLen && p + i + 1 < 4 + hsLen; i += 2) {
                u16 suite = getU16BE(body + p + i);
                if (suite == TLS_CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256) {
                    chosenCipher = suite;
                    break;
                }
                if (suite == TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256 && chosenCipher == 0) {
                    chosenCipher = suite;
                }
            }

            if (chosenCipher == 0) {
                return false;
            }

            return true;
        }

        offset += 4 + hsLen;
    }

    return false;
    VMProtectEnd();
}

bool TlsServerContext::sendServerHello(u16 cipherSuite) {
    crypto->generateRandomBytes(serverRandom, 32);

    byte msg[128];
    u32 pos = 0;

    u32 hsHeaderPos = pos;
    pos += 4;

    putU16BE(msg + pos, TLS_VERSION_12); pos += 2;
    SyscallManager::SecureMemCpy(msg + pos, serverRandom, 32); pos += 32;
    msg[pos++] = 0;
    putU16BE(msg + pos, cipherSuite); pos += 2;
    msg[pos++] = 0;

    u32 bodyLen = pos - hsHeaderPos - 4;
    msg[hsHeaderPos] = TLS_HS_SERVER_HELLO;
    putU24BE(msg + hsHeaderPos + 1, bodyLen);

    updateHandshakeHash(msg, pos);
    bool ok = sendRecord(TLS_CONTENT_HANDSHAKE, msg, pos);
    return ok;
    VMProtectEnd();
}

bool TlsServerContext::sendCertificate() {
    VMProtectBeginMutation("TlsServerContext_sendCertificate");
    u32 certMsgBodyLen = 3 + 3 + serverCertDerLen;
    u32 totalLen = 4 + certMsgBodyLen;

    byte* msg = new byte[totalLen];
    u32 pos = 0;

    msg[pos++] = TLS_HS_CERTIFICATE;
    putU24BE(msg + pos, certMsgBodyLen); pos += 3;

    putU24BE(msg + pos, 3 + serverCertDerLen); pos += 3;

    putU24BE(msg + pos, serverCertDerLen); pos += 3;
    SyscallManager::SecureMemCpy(msg + pos, serverCertDer, serverCertDerLen);
    pos += serverCertDerLen;

    updateHandshakeHash(msg, pos);
    bool ok = sendRecord(TLS_CONTENT_HANDSHAKE, msg, pos);
    delete[] msg;
    return ok;
    VMProtectEnd();
}

bool TlsServerContext::sendServerKeyExchange(const byte* ecdhPubRaw, u32 ecdhPubRawLen) {
    VMProtectBeginMutation("TlsServerContext_sendServerKeyExchange");
    byte ecParams[4 + 65];
    ecParams[0] = 0x03; // named_curve
    putU16BE(ecParams + 1, 0x0017); // secp256r1
    ecParams[3] = (byte)ecdhPubRawLen;
    SyscallManager::SecureMemCpy(ecParams + 4, ecdhPubRaw, ecdhPubRawLen);

    u32 toSignLen = 32 + 32 + 4 + ecdhPubRawLen;
    byte* toSign = new byte[toSignLen];
    SyscallManager::SecureMemCpy(toSign, clientRandom, 32);
    SyscallManager::SecureMemCpy(toSign + 32, serverRandom, 32);
    SyscallManager::SecureMemCpy(toSign + 64, ecParams, 4 + ecdhPubRawLen);

    // Sign with ECDSA (signEcdsa hashes internally with SHA-256, returns raw r||s)
    byte rawSig[256];
    u32 rawSigLen = 0;
    if (!crypto->signEcdsa(ecdsaPrivateKey, toSign, toSignLen, rawSig, &rawSigLen)) {
        delete[] toSign;
        return false;
    }
    delete[] toSign;

    // Convert raw r||s to DER-encoded signature (TLS expects DER)
    byte derSig[128];
    u32 derSigLen = 0;
    if (!X509CertBuilder::rawEcdsaToDer(rawSig, rawSigLen, derSig, &derSigLen)) {
        return false;
    }

    // Build full ServerKeyExchange message
    u32 skeBodyLen = 4 + ecdhPubRawLen + 2 + 2 + derSigLen;
    u32 totalLen = 4 + skeBodyLen;
    byte* msg = new byte[totalLen];
    u32 pos = 0;

    msg[pos++] = TLS_HS_SERVER_KEY_EXCHANGE;
    putU24BE(msg + pos, skeBodyLen); pos += 3;

    // ECDHE params
    SyscallManager::SecureMemCpy(msg + pos, ecParams, 4 + ecdhPubRawLen);
    pos += 4 + ecdhPubRawLen;

    // Signature algorithm: SHA-256 + ECDSA
    msg[pos++] = 0x04; // hash: SHA-256
    msg[pos++] = 0x03; // sig: ECDSA

    // Signature
    putU16BE(msg + pos, (u16)derSigLen); pos += 2;
    SyscallManager::SecureMemCpy(msg + pos, derSig, derSigLen);
    pos += derSigLen;

    updateHandshakeHash(msg, pos);
    bool ok = sendRecord(TLS_CONTENT_HANDSHAKE, msg, pos);
    delete[] msg;
    return ok;
    VMProtectEnd();
}

// ── sendServerHelloDone ─────────────────────────────────────────────────────

bool TlsServerContext::sendServerHelloDone() {
    VMProtectBeginMutation("TlsServerContext_sendServerHelloDone");
    byte msg[4];
    msg[0] = TLS_HS_SERVER_HELLO_DONE;
    putU24BE(msg + 1, 0); // zero-length body

    updateHandshakeHash(msg, 4);
    bool ok = sendRecord(TLS_CONTENT_HANDSHAKE, msg, 4);
    return ok;
    VMProtectEnd();
}

// ── recvClientKeyExchange ───────────────────────────────────────────────────

bool TlsServerContext::recvClientKeyExchange(byte* clientEcdhPub, u32& clientEcdhPubLen) {
    byte contentType = 0;
    byte recordData[16384];
    u32 recordLen = 0;
    if (!recvRecord(contentType, recordData, recordLen, sizeof(recordData))) {
        return false;
    }

    if (contentType != TLS_CONTENT_HANDSHAKE) return false;

    // Parse handshake message
    if (recordLen < 4) return false;
    if (recordData[0] != TLS_HS_CLIENT_KEY_EXCHANGE) return false;

    u32 hsLen = getU24BE(recordData + 1);

    // Update handshake hash
    updateHandshakeHash(recordData, 4 + hsLen);

    // ECDHE ClientKeyExchange: public_key_len(1) + public_key(N)
    byte* body = recordData + 4;
    if (hsLen < 1) return false;

    byte pubKeyLen = body[0];
    if (pubKeyLen + 1 > hsLen) return false;

    SyscallManager::SecureMemCpy(clientEcdhPub, body + 1, pubKeyLen);
    clientEcdhPubLen = pubKeyLen;

    return true;
    VMProtectEnd();
}

// ── recvClientChangeCipherSpecAndFinished ────────────────────────────────────

bool TlsServerContext::recvClientChangeCipherSpecAndFinished() {
    VMProtectBeginMutation("TlsServerContext_recvClientChangeCipherSpecAndFinished");
    // Receive ChangeCipherSpec
    byte contentType = 0;
    byte recordData[256];
    u32 recordLen = 0;

    if (!recvRecord(contentType, recordData, recordLen, sizeof(recordData))) {
        return false;
    }

    if (contentType != TLS_CONTENT_CHANGE_CIPHER || recordLen != 1 || recordData[0] != 1) {
        return false;
    }

    // Now client traffic is encrypted
    clientCipherActive = true;
    clientSeqNum = 0;

    // Receive encrypted client Finished
    if (!recvRecord(contentType, recordData, recordLen, sizeof(recordData))) {
        return false;
    }

    if (contentType != TLS_CONTENT_HANDSHAKE) {
        return false;
    }

    if (recordLen < 16) return false;
    if (recordData[0] != TLS_HS_FINISHED) return false;

    u32 finishedLen = getU24BE(recordData + 1);
    if (finishedLen != 12) return false;

    // Verify client finished
    byte hsHash[32];
    if (!getHandshakeHash(hsHash)) return false;

    byte expectedVerify[12];
    if (!prf(masterSecret, 48, "client finished", hsHash, 32, expectedVerify, 12)) {
        return false;
    }

    int diff = 0;
    for (int i = 0; i < 12; i++) {
        diff |= recordData[4 + i] ^ expectedVerify[i];
    }
    if (diff != 0) {
        return false;
    }

    // Add client Finished to handshake hash (needed for server Finished)
    updateHandshakeHash(recordData, recordLen);

    return true;
    VMProtectEnd();
}

// ── sendChangeCipherSpec ────────────────────────────────────────────────────

bool TlsServerContext::sendChangeCipherSpec() {
    VMProtectBeginMutation("TlsServerContext_sendChangeCipherSpec");
    byte ccs = 1;
    if (!sendRecord(TLS_CONTENT_CHANGE_CIPHER, &ccs, 1)) {
        return false;
    }
    cipherActive = true;
    serverSeqNum = 0;
    return true;
    VMProtectEnd();
}

// ── sendFinished ────────────────────────────────────────────────────────────

bool TlsServerContext::sendFinished() {
    VMProtectBeginMutation("TlsServerContext_sendFinished");
    byte hsHash[32];
    if (!getHandshakeHash(hsHash)) return false;

    byte verifyData[12];
    if (!prf(masterSecret, 48, "server finished", hsHash, 32, verifyData, 12)) {
        return false;
    }

    byte msg[16];
    msg[0] = TLS_HS_FINISHED;
    putU24BE(msg + 1, 12);
    SyscallManager::SecureMemCpy(msg + 4, verifyData, 12);

    bool ok = sendRecord(TLS_CONTENT_HANDSHAKE, msg, 16);
    return ok;
    VMProtectEnd();
}

// ── Key derivation ──────────────────────────────────────────────────────────

bool TlsServerContext::deriveKeys() {
    VMProtectBeginMutation("TlsServerContext_deriveKeys");
    // key_block = PRF(master_secret, "key expansion", server_random + client_random)
    // AES-128-GCM: client_write_key(16) + server_write_key(16) + client_write_IV(4) + server_write_IV(4) = 40
    byte seed[64];
    SyscallManager::SecureMemCpy(seed, serverRandom, 32);
    SyscallManager::SecureMemCpy(seed + 32, clientRandom, 32);

    byte keyBlock[40];
    if (!prf(masterSecret, 48, "key expansion", seed, 64, keyBlock, 40)) {
        return false;
    }

    SyscallManager::SecureMemCpy(clientWriteKey, keyBlock, 16);
    SyscallManager::SecureMemCpy(serverWriteKey, keyBlock + 16, 16);
    SyscallManager::SecureMemCpy(clientWriteIV, keyBlock + 32, 4);
    SyscallManager::SecureMemCpy(serverWriteIV, keyBlock + 36, 4);

    SyscallManager::SecureZero(keyBlock, 40);
    return true;
    VMProtectEnd();
}

// ── Handshake Hash (SHA-256 transcript) ─────────────────────────────────────

bool TlsServerContext::initHandshakeHash() {
    VMProtectBeginUltra("TlsServerContext_initHandshakeHash");
    DWORD objLen = 0;
    ULONG result = 0;
    BCryptGetProperty(hSha256, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &result, 0);

    handshakeHashObj = new byte[objLen];
    NTSTATUS s = BCryptCreateHash(hSha256, &hHandshakeHash, handshakeHashObj, objLen, nullptr, 0, 0);
    return BCRYPT_SUCCESS(s);
    VMProtectEnd();
}

bool TlsServerContext::updateHandshakeHash(const byte* data, u32 len) {
    VMProtectBeginUltra("TlsServerContext_updateHandshakeHash");
    if (!hHandshakeHash) return false;
    NTSTATUS s = BCryptHashData(hHandshakeHash, (PUCHAR)data, len, 0);
    return BCRYPT_SUCCESS(s);
    VMProtectEnd();
}

bool TlsServerContext::getHandshakeHash(byte* hashOut) {
    VMProtectBeginUltra("TlsServerContext_getHandshakeHash");
    if (!hHandshakeHash) return false;

    BCRYPT_HASH_HANDLE hDup = nullptr;
    NTSTATUS s = BCryptDuplicateHash(hHandshakeHash, &hDup, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(s)) return false;

    s = BCryptFinishHash(hDup, hashOut, 32, 0);
    BCryptDestroyHash(hDup);
    return BCRYPT_SUCCESS(s);
    VMProtectEnd();
}

// ── TLS PRF (P_SHA256) ─────────────────────────────────────────────────────

bool TlsServerContext::hmacSha256(const byte* key, u32 keyLen,
                                   const byte* data, u32 dataLen, byte* out) {
    VMProtectBeginUltra("TlsServerContext_hmacSha256");
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS s = BCryptCreateHash(hHmacSha256, &hHash, nullptr, 0,
                                   (PUCHAR)key, keyLen, BCRYPT_HASH_REUSABLE_FLAG);
    if (!BCRYPT_SUCCESS(s)) return false;

    s = BCryptHashData(hHash, (PUCHAR)data, dataLen, 0);
    if (!BCRYPT_SUCCESS(s)) { BCryptDestroyHash(hHash); return false; }

    s = BCryptFinishHash(hHash, out, 32, 0);
    BCryptDestroyHash(hHash);
    return BCRYPT_SUCCESS(s);
    VMProtectEnd();
}

bool TlsServerContext::prf(const byte* secret, u32 secretLen,
                            const char* label,
                            const byte* seed, u32 seedLen,
                            byte* output, u32 outputLen) {
    VMProtectBeginMutation("TlsServerContext_prf");
    u32 labelLen = 0;
    const char* p = label;
    while (*p) { labelLen++; p++; }

    u32 lsLen = labelLen + seedLen;
    byte* labelSeed = new byte[lsLen];
    SyscallManager::SecureMemCpy(labelSeed, label, labelLen);
    SyscallManager::SecureMemCpy(labelSeed + labelLen, seed, seedLen);

    byte a[32]; // A(i)
    if (!hmacSha256(secret, secretLen, labelSeed, lsLen, a)) {
        delete[] labelSeed;
        return false;
    }

    u32 generated = 0;
    byte* concat = new byte[32 + lsLen];

    while (generated < outputLen) {
        SyscallManager::SecureMemCpy(concat, a, 32);
        SyscallManager::SecureMemCpy(concat + 32, labelSeed, lsLen);

        byte block[32];
        if (!hmacSha256(secret, secretLen, concat, 32 + lsLen, block)) {
            delete[] labelSeed;
            delete[] concat;
            return false;
        }

        u32 copyLen = outputLen - generated;
        if (copyLen > 32) copyLen = 32;
        SyscallManager::SecureMemCpy(output + generated, block, copyLen);
        generated += copyLen;

        byte aNext[32];
        if (!hmacSha256(secret, secretLen, a, 32, aNext)) {
            delete[] labelSeed;
            delete[] concat;
            return false;
        }
        SyscallManager::SecureMemCpy(a, aNext, 32);
    }

    delete[] labelSeed;
    delete[] concat;
    return true;
    VMProtectEnd();
}

// ── AES-128-GCM ─────────────────────────────────────────────────────────────

bool TlsServerContext::aesGcmEncrypt(const byte* key, const byte* nonce,
                                      const byte* aad, u32 aadLen,
                                      const byte* plaintext, u32 plaintextLen,
                                      byte* ciphertext, byte* tag) {
    VMProtectBeginUltra("TlsServerContext_aesGcmEncrypt");
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS s = BCryptGenerateSymmetricKey(hAesGcm, &hKey, nullptr, 0,
                                             (PUCHAR)key, 16, 0);
    if (!BCRYPT_SUCCESS(s)) return false;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = 12;
    authInfo.pbAuthData = (PUCHAR)aad;
    authInfo.cbAuthData = aadLen;
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;

    DWORD cbResult = 0;
    s = BCryptEncrypt(hKey, (PUCHAR)plaintext, plaintextLen,
                      &authInfo, nullptr, 0,
                      ciphertext, plaintextLen, &cbResult, 0);

    BCryptDestroyKey(hKey);
    return BCRYPT_SUCCESS(s);
    VMProtectEnd();
}

bool TlsServerContext::aesGcmDecrypt(const byte* key, const byte* nonce,
                                      const byte* aad, u32 aadLen,
                                      const byte* ciphertext, u32 ciphertextLen,
                                      const byte* tag, byte* plaintext) {
    VMProtectBeginUltra("TlsServerContext_aesGcmDecrypt");
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS s = BCryptGenerateSymmetricKey(hAesGcm, &hKey, nullptr, 0,
                                             (PUCHAR)key, 16, 0);
    if (!BCRYPT_SUCCESS(s)) return false;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = 12;
    authInfo.pbAuthData = (PUCHAR)aad;
    authInfo.cbAuthData = aadLen;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = 16;

    DWORD cbResult = 0;
    s = BCryptDecrypt(hKey, (PUCHAR)ciphertext, ciphertextLen,
                      &authInfo, nullptr, 0,
                      plaintext, ciphertextLen, &cbResult, 0);

    BCryptDestroyKey(hKey);
    return BCRYPT_SUCCESS(s);
    VMProtectEnd();
}