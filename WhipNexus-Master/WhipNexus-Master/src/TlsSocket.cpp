#pragma optimize("", off)
#include "whipnexus/TlsSocket.h"

#include <stdio.h>
#include <windows.h>

#include "whipnexus/SyscallManager.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

__forceinline void TlsSocket::putU16BE(byte* dst, u16 val) {
    dst[0] = (byte)(val >> 8);
    dst[1] = (byte)(val);
}
__forceinline void TlsSocket::putU24BE(byte* dst, u32 val) {
    dst[0] = (byte)(val >> 16);
    dst[1] = (byte)(val >> 8);
    dst[2] = (byte)(val);
}
__forceinline void TlsSocket::putU64BE(byte* dst, u64 val) {
    for (int i = 7; i >= 0; i--) {
        dst[7 - i] = (byte)(val >> (i * 8));
    }
}
__forceinline u16 TlsSocket::getU16BE(const byte* src) {
    u16 result = ((u16)src[0] << 8) | src[1];
    return result;
}
__forceinline u32 TlsSocket::getU24BE(const byte* src) {
    u32 result = ((u32)src[0] << 16) | ((u32)src[1] << 8) | src[2];
    return result;
}

TlsSocket::TlsSocket()
    : crypto(nullptr), hAesGcm(nullptr), hSha256(nullptr), hSha384(nullptr),
      hHmacSha256(nullptr), hHmacSha384(nullptr),
      clientSeqNum(0), serverSeqNum(0),
      hsClientSeqNum(0), hsServerSeqNum(0),
      handshakeHash(nullptr), hHandshakeHash(nullptr),
      serverCertPubKeyLen(0), negotiatedCipher(0),
      tlsEstablished(false), cipherActive(false), plainMode(false),
      isTls13(false), handshakeKeysActive(false),
      clientEcdhPrivKey(nullptr), serverCertDerLen(0),
      recvBufStart(0), recvBufLen(0) {
    SyscallManager::SecureZero(clientRandom, 32);
    SyscallManager::SecureZero(serverRandom, 32);
    SyscallManager::SecureZero(masterSecret, 48);
    SyscallManager::SecureZero(clientWriteKey, 32);
    SyscallManager::SecureZero(serverWriteKey, 32);
    SyscallManager::SecureZero(serverCertPubKey, 256);
    SyscallManager::SecureZero(clientWriteIV, 4);
    SyscallManager::SecureZero(serverWriteIV, 4);
    SyscallManager::SecureZero(clientWriteIV13, 12);
    SyscallManager::SecureZero(serverWriteIV13, 12);
    SyscallManager::SecureZero(hsClientWriteKey, 32);
    SyscallManager::SecureZero(hsServerWriteKey, 32);
    SyscallManager::SecureZero(hsClientWriteIV, 12);
    SyscallManager::SecureZero(hsServerWriteIV, 12);
    SyscallManager::SecureZero(clientHsTrafficSecret, 48);
    SyscallManager::SecureZero(serverHsTrafficSecret, 48);
    SyscallManager::SecureZero(handshakeSecret, 48);
    SyscallManager::SecureZero(serverCertDer, 4096);
}

TlsSocket::~TlsSocket() {
    disconnect();
    cleanupAlgorithms();
}

bool TlsSocket::initAlgorithms() {
    VMProtectBeginUltra("TlsSocket_initAlgorithms");
    NTSTATUS s;

    s = BCryptOpenAlgorithmProvider(&hAesGcm, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(s)) { VMProtectEnd(); return false; }
    s = BCryptSetProperty(hAesGcm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(s)) { VMProtectEnd(); return false; }

    s = BCryptOpenAlgorithmProvider(&hSha256, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(s)) { VMProtectEnd(); return false; }

    s = BCryptOpenAlgorithmProvider(&hSha384, BCRYPT_SHA384_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(s)) { VMProtectEnd(); return false; }

    s = BCryptOpenAlgorithmProvider(&hHmacSha256, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(s)) { VMProtectEnd(); return false; }

    s = BCryptOpenAlgorithmProvider(&hHmacSha384, BCRYPT_SHA384_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(s)) { VMProtectEnd(); return false; }

    return true;
    VMProtectEnd();
}

void TlsSocket::cleanupAlgorithms() {
    if (hHandshakeHash) { BCryptDestroyHash(hHandshakeHash); hHandshakeHash = nullptr; }
    if (handshakeHash) { delete[] handshakeHash; handshakeHash = nullptr; }
    if (hAesGcm) { BCryptCloseAlgorithmProvider(hAesGcm, 0); hAesGcm = nullptr; }
    if (hSha256) { BCryptCloseAlgorithmProvider(hSha256, 0); hSha256 = nullptr; }
    if (hSha384) { BCryptCloseAlgorithmProvider(hSha384, 0); hSha384 = nullptr; }
    if (hHmacSha256) { BCryptCloseAlgorithmProvider(hHmacSha256, 0); hHmacSha256 = nullptr; }
    if (hHmacSha384) { BCryptCloseAlgorithmProvider(hHmacSha384, 0); hHmacSha384 = nullptr; }
}

void TlsSocket::init(SyscallResolver* res, CryptoService* cryptoService) {
    rawSocket.init(res);
    crypto = cryptoService;
}

bool TlsSocket::connect(const char* host, u16 port) {

    if (plainMode) {
        if (!rawSocket.connect(host, port)) {
            return false;
        }
        tlsEstablished = true;
        return true;
    }

    if (!initAlgorithms()) {
        return false;
    }

    if (!rawSocket.connect(host, port)) {
        return false;
    }

    if (!performTlsHandshake()) {
        rawSocket.disconnect();
        return false;
    }

    tlsEstablished = true;
    return true;
}

void TlsSocket::disconnect() {
    if (tlsEstablished && !plainMode) {
        // Best-effort TLS close-notify. If the server has stopped reading
        // (lockout/attach detection/exit), the send blocks until the TCP
        // send buffer drains — which never happens on a half-closed peer.
        // Cap with a 100ms socket-level send timeout: if it goes through
        // we send a polite alert; if not, TCP RST does the job.
        rawSocket.setTimeout(100);
        byte alert[2] = { 1, 0 };
        sendRecord(TLS_CONTENT_ALERT, alert, 2);
    }
    tlsEstablished = false;
    cipherActive = false;
    isTls13 = false;
    handshakeKeysActive = false;
    rawSocket.disconnect();
    recvBufStart = 0;
    recvBufLen = 0;
    clientSeqNum = 0;
    serverSeqNum = 0;
    hsClientSeqNum = 0;
    hsServerSeqNum = 0;

    SyscallManager::SecureZero(hsClientWriteKey, 32);
    SyscallManager::SecureZero(hsServerWriteKey, 32);
    SyscallManager::SecureZero(hsClientWriteIV, 12);
    SyscallManager::SecureZero(hsServerWriteIV, 12);
    SyscallManager::SecureZero(clientHsTrafficSecret, 48);
    SyscallManager::SecureZero(serverHsTrafficSecret, 48);
    SyscallManager::SecureZero(handshakeSecret, 48);
    SyscallManager::SecureZero(clientWriteIV13, 12);
    SyscallManager::SecureZero(serverWriteIV13, 12);
    SyscallManager::SecureZero(masterSecret, 48);

    if (clientEcdhPrivKey) {
        crypto->freeKeyHandle(clientEcdhPrivKey);
        clientEcdhPrivKey = nullptr;
    }
}

bool TlsSocket::isConnected() const {
    if (plainMode) { return rawSocket.isConnected(); }
    return tlsEstablished && rawSocket.isConnected();
}

bool TlsSocket::setTimeout(u32 timeoutMs) {
    return rawSocket.setTimeout(timeoutMs);
}

bool TlsSocket::send(const byte* data, u32 length) {
    // VMProtect removed for performance (I/O hot path)
    if (!tlsEstablished) { return false; }

    if (plainMode) {
        return rawSocket.send(data, length);
    }

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
}

i32 TlsSocket::receive(byte* buffer, u32 bufferSize) {
    // VMProtect removed for performance (called hundreds of times)
    if (!tlsEstablished) { return -1; }

    if (plainMode) {
        i32 result = rawSocket.receive(buffer, bufferSize);
        return result;
    }

    if (recvBufLen > 0) {
        u32 copyLen = recvBufLen < bufferSize ? recvBufLen : bufferSize;
        SyscallManager::SecureMemCpy(buffer, recvBuf + recvBufStart, copyLen);
        recvBufStart += copyLen;
        recvBufLen -= copyLen;
        return (i32)copyLen;
    }

    byte contentType = 0;
    u32 recordLen = 0;
    if (!recvRecord(contentType, recordBuf, recordLen, RECORD_BUF_SIZE)) {
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
}

bool TlsSocket::receiveExact(byte* buffer, u32 length) {
    if (plainMode) {
        return rawSocket.receiveExact(buffer, length);
    }

    u32 totalRecv = 0;
    while (totalRecv < length) {
        i32 received = receive(buffer + totalRecv, length - totalRecv);
        if (received <= 0) {
            return false;
        }
        totalRecv += (u32)received;
    }

    return true;
}

bool TlsSocket::sendRecord(byte contentType, const byte* data, u32 len) {
    // VMProtect removed for performance (called for every TLS record)
    if (cipherActive && isTls13) {
        u32 innerLen = len + 1;
        byte* innerPlaintext = new byte[innerLen];
        SyscallManager::SecureMemCpy(innerPlaintext, data, len);
        innerPlaintext[len] = contentType;

        const byte* writeKey;
        const byte* writeIV;
        u64* seqNum;
        if (handshakeKeysActive) {
            writeKey = hsClientWriteKey;
            writeIV = hsClientWriteIV;
            seqNum = &hsClientSeqNum;
        } else {
            writeKey = clientWriteKey;
            writeIV = clientWriteIV13;
            seqNum = &clientSeqNum;
        }

        byte nonce[12];
        byte seqBytes[12];
        SyscallManager::SecureZero(seqBytes, 12);
        putU64BE(seqBytes + 4, *seqNum);
        for (int i = 0; i < 12; i++) {
            nonce[i] = writeIV[i] ^ seqBytes[i];
        }

        byte header[5];
        header[0] = TLS_CONTENT_APPLICATION;
        putU16BE(header + 1, TLS_VERSION_12);
        putU16BE(header + 3, (u16)(innerLen + 16));

        byte* ciphertext = new byte[innerLen];
        byte tag[16];
        if (!aesGcmEncrypt(writeKey, nonce, header, 5, innerPlaintext, innerLen, ciphertext, tag)) {
            delete[] innerPlaintext;
            delete[] ciphertext;
            return false;
        }
        delete[] innerPlaintext;

        bool ok = rawSocket.send(header, 5) &&
                  rawSocket.send(ciphertext, innerLen) &&
                  rawSocket.send(tag, 16);

        delete[] ciphertext;
        (*seqNum)++;
        return ok;

    } else if (cipherActive) {
        byte nonce[12];
        SyscallManager::SecureMemCpy(nonce, clientWriteIV, 4);
        putU64BE(nonce + 4, clientSeqNum);

        byte explicitNonce[8];
        putU64BE(explicitNonce, clientSeqNum);

        byte aad[13];
        putU64BE(aad, clientSeqNum);
        aad[8] = contentType;
        putU16BE(aad + 9, TLS_VERSION_12);
        putU16BE(aad + 11, (u16)len);

        byte* ciphertext = new byte[len];
        byte tag[16];
        if (!aesGcmEncrypt(clientWriteKey, nonce, aad, 13, data, len, ciphertext, tag)) {
            delete[] ciphertext;
            return false;
        }

        u32 recordPayloadLen = 8 + len + 16;
        byte header[5];
        header[0] = contentType;
        putU16BE(header + 1, TLS_VERSION_12);
        putU16BE(header + 3, (u16)recordPayloadLen);

        bool ok = rawSocket.send(header, 5) &&
                  rawSocket.send(explicitNonce, 8) &&
                  rawSocket.send(ciphertext, len) &&
                  rawSocket.send(tag, 16);

        delete[] ciphertext;
        clientSeqNum++;
        return ok;
    } else {
        byte header[5];
        header[0] = contentType;
        putU16BE(header + 1, TLS_VERSION_12);
        putU16BE(header + 3, (u16)len);

        bool result = rawSocket.send(header, 5) && rawSocket.send(data, len);
        return result;
    }
}

bool TlsSocket::recvRecord(byte& contentType, byte* data, u32& len, u32 maxLen) {
    // VMProtect removed for performance (called for every TLS record)
    LARGE_INTEGER netStart, netEnd, decryptStart, decryptEnd, freq;
    QueryPerformanceFrequency(&freq);

    QueryPerformanceCounter(&netStart);
    byte header[5];
    if (!rawSocket.receiveExact(header, 5)) { return false; }

    contentType = header[0];
    u16 recordLen = getU16BE(header + 3);

    if (recordLen > RAW_BUF_SIZE) { return false; }

    if (!rawSocket.receiveExact(rawRecvBuf, recordLen)) { return false; }
    QueryPerformanceCounter(&netEnd);

    double netTimeMs = ((double)(netEnd.QuadPart - netStart.QuadPart) * 1000.0) / (double)freq.QuadPart;

    if (isTls13 && cipherActive && contentType == TLS_CONTENT_APPLICATION) {
        char buf[256];
        sprintf_s(buf, "[TLS] Received TLS 1.3 record, len=%u\n", recordLen);

        if (recordLen < 17) {
            return false;
        }

        u32 ciphertextLen = recordLen - 16;
        sprintf_s(buf, "[TLS] Ciphertext len=%u\n", ciphertextLen);

        byte* ciphertext = rawRecvBuf;
        byte* tag = rawRecvBuf + ciphertextLen;

        const byte* readKey;
        const byte* readIV;
        u64* seqNum;
        if (handshakeKeysActive) {
            readKey = hsServerWriteKey;
            readIV = hsServerWriteIV;
            seqNum = &hsServerSeqNum;
        } else {
            readKey = serverWriteKey;
            readIV = serverWriteIV13;
            seqNum = &serverSeqNum;
        }

        byte nonce[12];
        byte seqBytes[12];
        SyscallManager::SecureZero(seqBytes, 12);
        putU64BE(seqBytes + 4, *seqNum);
        for (int i = 0; i < 12; i++) {
            nonce[i] = readIV[i] ^ seqBytes[i];
        }

        if (ciphertextLen > maxLen) {
            return false;
        }

        QueryPerformanceCounter(&decryptStart);

        u32 allocSize = ciphertextLen + 4096;

        byte* plaintextRaw = new byte[allocSize];
        byte* plaintext = (byte*)(((uintptr_t)plaintextRaw + 31) & ~31);

        bool decryptSuccess = false;

        if (ciphertextLen > 8192) {

            DecryptTask task;
            task.socket = this;
            SyscallManager::SecureMemCpy(task.key, readKey, 32);
            SyscallManager::SecureMemCpy(task.nonce, nonce, 12);
            SyscallManager::SecureMemCpy(task.aad, header, 5);
            task.aadLen = 5;
            task.ciphertext = ciphertext;
            task.ciphertextLen = ciphertextLen;
            task.tag = tag;
            task.plaintext = plaintext;
            task.complete = false;
            task.success = false;

            u32 threadId = 0;
            void* hThread = SyscallManager::CreateThread((void*)decryptTaskEntry, &task, &threadId);

            if (hThread) {
                SyscallManager::WaitForThread(hThread, 5000);
                SyscallManager::CloseHandle(hThread);
                decryptSuccess = task.success;
            } else {
                decryptSuccess = aesGcmDecrypt(readKey, nonce, header, 5, ciphertext, ciphertextLen, tag, plaintext);
            }
        } else {
            decryptSuccess = aesGcmDecrypt(readKey, nonce, header, 5, ciphertext, ciphertextLen, tag, plaintext);
        }

        QueryPerformanceCounter(&decryptEnd);

        double decryptTimeMs = ((double)(decryptEnd.QuadPart - decryptStart.QuadPart) * 1000.0) / (double)freq.QuadPart;

        static double totalNetMs = 0.0, totalDecryptMs = 0.0;
        static int recordCount = 0;
        totalNetMs += netTimeMs;
        totalDecryptMs += decryptTimeMs;
        recordCount++;

        (*seqNum)++;

        if (!decryptSuccess) {
            delete[] plaintextRaw;
            return false;
        }


        u32 realLen = ciphertextLen;
        while (realLen > 0 && plaintext[realLen - 1] == 0) {
            realLen--;
        }
        if (realLen == 0) {
            delete[] plaintextRaw;
            return false;
        }
        contentType = plaintext[realLen - 1];
        realLen--;
        if (realLen > maxLen) {
            delete[] plaintextRaw;
            return false;
        }

        sprintf_s(buf, "[TLS] Copying %u bytes to output\n", realLen);

        SyscallManager::SecureMemCpy(data, plaintext, realLen);
        len = realLen;
        delete[] plaintextRaw;

        return true;

    } else if (cipherActive && contentType == TLS_CONTENT_APPLICATION) {
        if (recordLen < 24) { return false; }

        byte* explicitNonce = rawRecvBuf;
        u32 ciphertextLen = recordLen - 8 - 16;
        byte* ciphertext = rawRecvBuf + 8;
        byte* tag = rawRecvBuf + 8 + ciphertextLen;

        byte nonce[12];
        SyscallManager::SecureMemCpy(nonce, serverWriteIV, 4);
        SyscallManager::SecureMemCpy(nonce + 4, explicitNonce, 8);

        byte aad[13];
        putU64BE(aad, serverSeqNum);
        aad[8] = contentType;
        putU16BE(aad + 9, TLS_VERSION_12);
        putU16BE(aad + 11, (u16)ciphertextLen);

        if (ciphertextLen > maxLen) { return false; }

        if (!aesGcmDecrypt(serverWriteKey, nonce, aad, 13, ciphertext, ciphertextLen, tag, data)) {
            return false;
        }

        len = ciphertextLen;
        serverSeqNum++;
        return true;

    } else if (cipherActive && contentType == TLS_CONTENT_HANDSHAKE) {
        if (recordLen < 24) { return false; }

        byte* explicitNonce = rawRecvBuf;
        u32 ciphertextLen = recordLen - 8 - 16;
        byte* ciphertext = rawRecvBuf + 8;
        byte* tag = rawRecvBuf + 8 + ciphertextLen;

        byte nonce[12];
        SyscallManager::SecureMemCpy(nonce, serverWriteIV, 4);
        SyscallManager::SecureMemCpy(nonce + 4, explicitNonce, 8);

        byte aad[13];
        putU64BE(aad, serverSeqNum);
        aad[8] = contentType;
        putU16BE(aad + 9, TLS_VERSION_12);
        putU16BE(aad + 11, (u16)ciphertextLen);

        if (ciphertextLen > maxLen) { return false; }

        if (!aesGcmDecrypt(serverWriteKey, nonce, aad, 13, ciphertext, ciphertextLen, tag, data)) {
            return false;
        }

        len = ciphertextLen;
        serverSeqNum++;
        return true;

    } else {
        if (recordLen > maxLen) { return false; }
        SyscallManager::SecureMemCpy(data, rawRecvBuf, recordLen);
        len = recordLen;
        return true;
    }
}

bool TlsSocket::hkdfExtract384(const byte* salt, u32 saltLen,
                                 const byte* ikm, u32 ikmLen,
                                 byte* prkOut) {
    return hmacSha384(salt, saltLen, ikm, ikmLen, prkOut);
}

bool TlsSocket::hkdfExpandLabel384(const byte* secret,
                                     const char* label, u32 labelLen,
                                     const byte* context, u32 contextLen,
                                     byte* output, u32 outputLen) {
    VMProtectBeginMutation("TlsSocket_hkdfExpandLabel384");
    static const char prefix[] = "tls13 ";
    u32 prefixLen = 6;
    u32 prefixedLabelLen = prefixLen + labelLen;

    byte hkdfLabel[512];
    u32 pos = 0;
    putU16BE(hkdfLabel + pos, (u16)outputLen); pos += 2;
    hkdfLabel[pos++] = (byte)prefixedLabelLen;
    SyscallManager::SecureMemCpy(hkdfLabel + pos, prefix, prefixLen); pos += prefixLen;
    SyscallManager::SecureMemCpy(hkdfLabel + pos, label, labelLen); pos += labelLen;
    hkdfLabel[pos++] = (byte)contextLen;
    if (contextLen > 0) {
        SyscallManager::SecureMemCpy(hkdfLabel + pos, context, contextLen);
        pos += contextLen;
    }

    byte t[48];
    u32 tLen = 0;
    u32 generated = 0;
    byte counter = 1;

    byte* input = new byte[48 + pos + 1];

    while (generated < outputLen) {
        u32 inputLen = 0;
        if (tLen > 0) {
            SyscallManager::SecureMemCpy(input, t, tLen);
            inputLen += tLen;
        }
        SyscallManager::SecureMemCpy(input + inputLen, hkdfLabel, pos);
        inputLen += pos;
        input[inputLen++] = counter;

        if (!hmacSha384(secret, 48, input, inputLen, t)) {
            delete[] input;
            VMProtectEnd();
            return false;
        }
        tLen = 48;

        u32 copyLen = outputLen - generated;
        if (copyLen > 48) copyLen = 48;
        SyscallManager::SecureMemCpy(output + generated, t, copyLen);
        generated += copyLen;
        counter++;
    }

    delete[] input;
    return true;
    VMProtectEnd();
}

bool TlsSocket::deriveTrafficKeys13(const byte* trafficSecret,
                                      byte* keyOut, byte* ivOut) {
    VMProtectBeginMutation("TlsSocket_deriveTrafficKeys13");
    if (!hkdfExpandLabel384(trafficSecret, "key", 3, nullptr, 0, keyOut, 32)) {
        return false;
    }
    if (!hkdfExpandLabel384(trafficSecret, "iv", 2, nullptr, 0, ivOut, 12)) {
        return false;
    }
    return true;
    VMProtectEnd();
}

bool TlsSocket::deriveHandshakeKeys(const byte* sharedSecret, u32 sharedSecretLen) {
    VMProtectBeginMutation("TlsSocket_deriveHandshakeKeys");
    byte zeros48[48];
    SyscallManager::SecureZero(zeros48, 48);

    byte earlySecret[48];
    if (!hkdfExtract384(zeros48, 48, zeros48, 48, earlySecret)) {
        return false;
    }

    byte emptyHash[48];
    {
        BCRYPT_HASH_HANDLE hHash = nullptr;
        NTSTATUS s = BCryptCreateHash(hSha384, &hHash, nullptr, 0, nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(s)) { return false; }
        s = BCryptFinishHash(hHash, emptyHash, 48, 0);
        BCryptDestroyHash(hHash);
        if (!BCRYPT_SUCCESS(s)) { return false; }
    }

    byte derived[48];
    if (!hkdfExpandLabel384(earlySecret, "derived", 7, emptyHash, 48, derived, 48)) {
        return false;
    }

    if (!hkdfExtract384(derived, 48, sharedSecret, sharedSecretLen, handshakeSecret)) {
        return false;
    }

    byte transcriptHash[48];
    if (!getHandshakeHash(transcriptHash)) { VMProtectEnd(); return false; }

    if (!hkdfExpandLabel384(handshakeSecret, "c hs traffic", 12, transcriptHash, 48,
                            clientHsTrafficSecret, 48)) {
        return false;
    }

    if (!hkdfExpandLabel384(handshakeSecret, "s hs traffic", 12, transcriptHash, 48,
                            serverHsTrafficSecret, 48)) {
        return false;
    }

    if (!deriveTrafficKeys13(clientHsTrafficSecret, hsClientWriteKey, hsClientWriteIV)) {
        return false;
    }
    if (!deriveTrafficKeys13(serverHsTrafficSecret, hsServerWriteKey, hsServerWriteIV)) {
        return false;
    }

    return true;
    VMProtectEnd();
}

bool TlsSocket::deriveApplicationKeys() {
    VMProtectBeginMutation("TlsSocket_deriveApplicationKeys");
    byte emptyHash[48];
    {
        BCRYPT_HASH_HANDLE hHash = nullptr;
        NTSTATUS s = BCryptCreateHash(hSha384, &hHash, nullptr, 0, nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(s)) { VMProtectEnd(); return false; }
        s = BCryptFinishHash(hHash, emptyHash, 48, 0);
        BCryptDestroyHash(hHash);
        if (!BCRYPT_SUCCESS(s)) { VMProtectEnd(); return false; }
    }

    byte derived2[48];
    if (!hkdfExpandLabel384(handshakeSecret, "derived", 7, emptyHash, 48, derived2, 48)) {
        return false;
    }

    byte zeros48[48];
    SyscallManager::SecureZero(zeros48, 48);
    byte masterSec[48];
    if (!hkdfExtract384(derived2, 48, zeros48, 48, masterSec)) {
        return false;
    }

    byte transcriptHash[48];
    if (!getHandshakeHash(transcriptHash)) { VMProtectEnd(); return false; }

    byte clientAppTrafficSecret[48];
    if (!hkdfExpandLabel384(masterSec, "c ap traffic", 12, transcriptHash, 48,
                            clientAppTrafficSecret, 48)) {
        return false;
    }

    byte serverAppTrafficSecret[48];
    if (!hkdfExpandLabel384(masterSec, "s ap traffic", 12, transcriptHash, 48,
                            serverAppTrafficSecret, 48)) {
        return false;
    }

    byte appClientKey[32], appClientIV[12];
    byte appServerKey[32], appServerIV[12];
    if (!deriveTrafficKeys13(clientAppTrafficSecret, appClientKey, appClientIV)) {
        return false;
    }
    if (!deriveTrafficKeys13(serverAppTrafficSecret, appServerKey, appServerIV)) {
        return false;
    }

    SyscallManager::SecureMemCpy(clientWriteKey, appClientKey, 32);
    SyscallManager::SecureMemCpy(clientWriteIV13, appClientIV, 12);
    SyscallManager::SecureMemCpy(serverWriteKey, appServerKey, 32);
    SyscallManager::SecureMemCpy(serverWriteIV13, appServerIV, 12);

    SyscallManager::SecureZero(clientAppTrafficSecret, 48);
    SyscallManager::SecureZero(serverAppTrafficSecret, 48);
    SyscallManager::SecureZero(masterSec, 48);
    return true;
    VMProtectEnd();

}

bool TlsSocket::verifyCertificateVerify13(const byte* signature, u32 sigLen, u16 sigAlgorithm) {
    VMProtectBeginMutation("TlsSocket_verifyCertificateVerify13");
    byte signedData[147];
    for (int i = 0; i < 64; i++) signedData[i] = 0x20;

    static const char context[] = "TLS 1.3, server CertificateVerify";
    SyscallManager::SecureMemCpy(signedData + 64, context, 33);
    signedData[97] = 0x00;

    byte transcriptHash[48];
    if (!getHandshakeHash(transcriptHash)) { VMProtectEnd(); return false; }
    SyscallManager::SecureMemCpy(signedData + 98, transcriptHash, 48);

    byte correctSignedData[146];
    for (int i = 0; i < 64; i++) correctSignedData[i] = 0x20;
    SyscallManager::SecureMemCpy(correctSignedData + 64, context, 33);
    correctSignedData[97] = 0x00;
    SyscallManager::SecureMemCpy(correctSignedData + 98, transcriptHash, 48);

    if (sigAlgorithm == 0x0403) {
        byte hash[32];
        BCRYPT_HASH_HANDLE hHash = nullptr;
        NTSTATUS s = BCryptCreateHash(hSha256, &hHash, nullptr, 0, nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(s)) { VMProtectEnd(); return false; }
        BCryptHashData(hHash, (PUCHAR)correctSignedData, 146, 0);
        BCryptFinishHash(hHash, hash, 32, 0);
        BCryptDestroyHash(hHash);

        if (crypto->verifyEcdsa(serverCertPubKey, serverCertPubKeyLen,
                                hash, 32, signature, sigLen, true)) {
            return true;
        }
        return false;

    } else if (sigAlgorithm == 0x0804) {
        byte hash[32];
        BCRYPT_HASH_HANDLE hHash = nullptr;
        NTSTATUS s = BCryptCreateHash(hSha256, &hHash, nullptr, 0, nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(s)) { return false; }
        BCryptHashData(hHash, (PUCHAR)correctSignedData, 146, 0);
        BCryptFinishHash(hHash, hash, 32, 0);
        BCryptDestroyHash(hHash);

        BCRYPT_KEY_HANDLE hRsaKey = nullptr;
        CERT_PUBLIC_KEY_INFO* pubKeyInfo = nullptr;
        DWORD pubKeyInfoLen = 0;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                                  serverCertPubKey, serverCertPubKeyLen,
                                  CRYPT_DECODE_ALLOC_FLAG, nullptr,
                                  &pubKeyInfo, &pubKeyInfoLen)) {
            return false;
        }

        if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pubKeyInfo, 0, nullptr, &hRsaKey)) {
            LocalFree(pubKeyInfo);
            return false;
        }
        LocalFree(pubKeyInfo);

        BCRYPT_PSS_PADDING_INFO pssInfo;
        pssInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        pssInfo.cbSalt = 32;

        s = BCryptVerifySignature(hRsaKey, &pssInfo,
                                   hash, 32,
                                   (PUCHAR)signature, sigLen,
                                   BCRYPT_PAD_PSS);

        BCryptDestroyKey(hRsaKey);

        if (BCRYPT_SUCCESS(s)) {
            return true;
        }
        return false;
    }

    return false;
    VMProtectEnd();
}

bool TlsSocket::validateSelfSignedCert(const byte* certDer, u32 certDerLen) {
    VMProtectBeginMutation("TlsSocket_validateSelfSignedCert");
    if (certDerLen < 4 || certDer[0] != 0x30) { return false; }

    u32 outerHeaderSize = 2;
    u32 outerContentLen = 0;
    if (certDer[1] < 0x80) {
        outerContentLen = certDer[1];
    } else if (certDer[1] == 0x81) {
        outerContentLen = certDer[2];
        outerHeaderSize = 3;
    } else if (certDer[1] == 0x82) {
        outerContentLen = ((u32)certDer[2] << 8) | certDer[3];
        outerHeaderSize = 4;
    } else if (certDer[1] == 0x83) {
        outerContentLen = ((u32)certDer[2] << 16) | ((u32)certDer[3] << 8) | certDer[4];
        outerHeaderSize = 5;
    } else {
        return false;
    }

    u32 pos = outerHeaderSize;

    if (pos >= certDerLen || certDer[pos] != 0x30) { return false; }
    u32 tbsStart = pos;
    u32 tbsHeaderSize = 2;
    u32 tbsContentLen = 0;
    if (certDer[pos + 1] < 0x80) {
        tbsContentLen = certDer[pos + 1];
    } else if (certDer[pos + 1] == 0x81) {
        tbsContentLen = certDer[pos + 2];
        tbsHeaderSize = 3;
    } else if (certDer[pos + 1] == 0x82) {
        tbsContentLen = ((u32)certDer[pos + 2] << 8) | certDer[pos + 3];
        tbsHeaderSize = 4;
    } else if (certDer[pos + 1] == 0x83) {
        tbsContentLen = ((u32)certDer[pos + 2] << 16) | ((u32)certDer[pos + 3] << 8) | certDer[pos + 4];
        tbsHeaderSize = 5;
    } else {
        return false;
    }
    u32 tbsTotalLen = tbsHeaderSize + tbsContentLen;
    pos += tbsTotalLen;

    byte tbsHash[32];
    {
        BCRYPT_HASH_HANDLE hHash = nullptr;
        NTSTATUS s = BCryptCreateHash(hSha256, &hHash, nullptr, 0, nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(s)) { return false; }
        BCryptHashData(hHash, (PUCHAR)(certDer + tbsStart), tbsTotalLen, 0);
        BCryptFinishHash(hHash, tbsHash, 32, 0);
        BCryptDestroyHash(hHash);
    }

    if (pos >= certDerLen || certDer[pos] != 0x30) { return false; }
    u32 sigAlgHeaderSize = 2;
    u32 sigAlgLen = 0;
    if (certDer[pos + 1] < 0x80) {
        sigAlgLen = certDer[pos + 1];
    } else if (certDer[pos + 1] == 0x81) {
        sigAlgLen = certDer[pos + 2];
        sigAlgHeaderSize = 3;
    } else {
        return false;
    }
    pos += sigAlgHeaderSize + sigAlgLen;

    if (pos >= certDerLen || certDer[pos] != 0x03) { return false; }
    pos++;
    u32 sigBitStrLen = 0;
    if (certDer[pos] < 0x80) {
        sigBitStrLen = certDer[pos++];
    } else if (certDer[pos] == 0x81) {
        sigBitStrLen = certDer[pos + 1];
        pos += 2;
    } else if (certDer[pos] == 0x82) {
        sigBitStrLen = ((u32)certDer[pos + 1] << 8) | certDer[pos + 2];
        pos += 3;
    } else {
        return false;
    }

    if (pos >= certDerLen) { return false; }
    pos++;
    u32 sigLen = sigBitStrLen - 1;

    if (pos + sigLen > certDerLen) { return false; }
    const byte* sig = certDer + pos;

    if (crypto->verifyEcdsa(serverCertPubKey, serverCertPubKeyLen,
                            tbsHash, 32, sig, sigLen, true)) {
        return true;
    }

    BCRYPT_KEY_HANDLE hRsaKey = nullptr;
    CERT_PUBLIC_KEY_INFO* pubKeyInfo = nullptr;
    DWORD pubKeyInfoLen = 0;
    if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                              serverCertPubKey, serverCertPubKeyLen,
                              CRYPT_DECODE_ALLOC_FLAG, nullptr,
                              &pubKeyInfo, &pubKeyInfoLen)) {
        if (CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pubKeyInfo, 0, nullptr, &hRsaKey)) {
            BCRYPT_PKCS1_PADDING_INFO paddingInfo;
            paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

            NTSTATUS s = BCryptVerifySignature(hRsaKey, &paddingInfo,
                                               tbsHash, 32,
                                               (PUCHAR)sig, sigLen,
                                               BCRYPT_PAD_PKCS1);
            BCryptDestroyKey(hRsaKey);
            LocalFree(pubKeyInfo);

            if (BCRYPT_SUCCESS(s)) {
                return true;
            }
        } else {
            LocalFree(pubKeyInfo);
        }
    }

    return false;
    VMProtectEnd();
}

bool TlsSocket::computeFinishedVerify13(const byte* baseKey, byte* verifyDataOut) {
    VMProtectBeginMutation("TlsSocket_computeFinishedVerify13");
    byte finishedKey[48];
    if (!hkdfExpandLabel384(baseKey, "finished", 8, nullptr, 0, finishedKey, 48)) {
        return false;
    }

    byte transcriptHash[48];
    if (!getHandshakeHash(transcriptHash)) { return false; }

    if (!hmacSha384(finishedKey, 48, transcriptHash, 48, verifyDataOut)) {
        return false;
    }

    SyscallManager::SecureZero(finishedKey, 48);
    return true;
    VMProtectEnd();
}

bool TlsSocket::sendClientFinished13() {
    VMProtectBeginMutation("TlsSocket_sendClientFinished13");
    byte verifyData[48];
    if (!computeFinishedVerify13(clientHsTrafficSecret, verifyData)) {
        return false;
    }

    byte msg[52];
    msg[0] = TLS_HS_FINISHED;
    putU24BE(msg + 1, 48);
    SyscallManager::SecureMemCpy(msg + 4, verifyData, 48);

    updateHandshakeHash(msg, 52);

    bool result = sendRecord(TLS_CONTENT_HANDSHAKE, msg, 52);
    return result;
    VMProtectEnd();
}

bool TlsSocket::processEncryptedHandshakeMessages() {
    VMProtectBeginMutation("TlsSocket_processEncryptedHandshakeMessages");
    bool gotEncryptedExtensions = false;
    bool gotCertificate = false;
    bool gotCertificateVerify = false;
    bool gotFinished = false;

    while (!gotFinished) {
        byte contentType = 0;
        byte recordData[16384];
        u32 recordLen = 0;

        if (!recvRecord(contentType, recordData, recordLen, sizeof(recordData))) {
            return false;
        }

        if (contentType == TLS_CONTENT_CHANGE_CIPHER) {
            continue;
        }

        if (contentType != TLS_CONTENT_HANDSHAKE) {
            if (contentType == TLS_CONTENT_ALERT) {
            }
            return false;
        }

        u32 offset = 0;
        while (offset < recordLen) {
            if (offset + 4 > recordLen) { return false; }

            byte hsType = recordData[offset];
            u32 hsLen = getU24BE(recordData + offset + 1);

            if (offset + 4 + hsLen > recordLen) { return false; }

            byte* hsBody = recordData + offset + 4;

            switch (hsType) {
                case TLS_HS_ENCRYPTED_EXTENSIONS: {
                    updateHandshakeHash(recordData + offset, 4 + hsLen);
                    gotEncryptedExtensions = true;
                    break;
                }

                case TLS_HS_CERTIFICATE: {
                    if (hsLen < 4) { return false; }
                    u32 ctxLen = hsBody[0];
                    u32 p = 1 + ctxLen;

                    if (p + 3 > hsLen) { return false; }
                    u32 certListLen = getU24BE(hsBody + p);
                    p += 3;

                    if (p + certListLen > hsLen) { return false; }
                    if (certListLen < 3) { return false; }

                    u32 certLen = getU24BE(hsBody + p);
                    p += 3;

                    if (p + certLen > hsLen) { return false; }
                    const byte* certData = hsBody + p;
                    p += certLen;

                    if (certLen <= sizeof(serverCertDer)) {
                        SyscallManager::SecureMemCpy(serverCertDer, certData, certLen);
                        serverCertDerLen = certLen;
                    }

                    if (p + 2 <= hsLen) {
                        u16 certExtLen = getU16BE(hsBody + p);
                        p += 2 + certExtLen;
                    }

                    static const byte ecP256Oid[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
                    static const byte rsaOid[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

                    serverCertPubKeyLen = 0;
                    for (u32 i = 0; i + 10 < certLen; i++) {
                        if (certData[i] != 0x30) continue;

                        u32 seqStart = i;
                        u32 li = i + 1;
                        u32 seqContentLen = 0;
                        u32 headerSize = 2;
                        if (certData[li] < 0x80) {
                            seqContentLen = certData[li];
                        } else if (certData[li] == 0x81 && li + 1 < certLen) {
                            seqContentLen = certData[li + 1];
                            headerSize = 3;
                        } else if (certData[li] == 0x82 && li + 2 < certLen) {
                            seqContentLen = ((u32)certData[li + 1] << 8) | certData[li + 2];
                            headerSize = 4;
                        } else {
                            continue;
                        }

                        u32 seqTotalLen = headerSize + seqContentLen;
                        if (seqStart + seqTotalLen > certLen) continue;

                        const byte* seqContent = certData + seqStart + headerSize;
                        bool isEc = false;
                        bool isRsa = false;
                        for (u32 j = 0; j + 10 <= seqContentLen; j++) {
                            if (!isEc && j + 10 <= seqContentLen) {
                                bool match = true;
                                for (u32 k = 0; k < 10; k++) {
                                    if (seqContent[j + k] != ecP256Oid[k]) { match = false; break; }
                                }
                                if (match) isEc = true;
                            }
                            if (!isRsa && j + 11 <= seqContentLen) {
                                bool match = true;
                                for (u32 k = 0; k < 11; k++) {
                                    if (seqContent[j + k] != rsaOid[k]) { match = false; break; }
                                }
                                if (match) isRsa = true;
                            }
                        }

                        if (isEc || isRsa) {
                            if (seqTotalLen <= sizeof(serverCertPubKey)) {
                                SyscallManager::SecureMemCpy(serverCertPubKey, certData + seqStart, seqTotalLen);
                                serverCertPubKeyLen = seqTotalLen;
                                break;
                            }
                        }
                    }

                    if (serverCertPubKeyLen == 0) {
                        return false;
                    }

                    if (!validateSelfSignedCert(certData, certLen)) {
                        return false;
                    }

                    updateHandshakeHash(recordData + offset, 4 + hsLen);
                    gotCertificate = true;
                    break;
                }

                case TLS_HS_CERTIFICATE_VERIFY: {
                    if (hsLen < 4) { return false; }
                    u16 sigAlgorithm = getU16BE(hsBody);
                    u16 sigLen = getU16BE(hsBody + 2);

                    if (4 + sigLen > hsLen) { return false; }
                    const byte* sig = hsBody + 4;

                    if (!verifyCertificateVerify13(sig, sigLen, sigAlgorithm)) {
                        return false;
                    }

                    updateHandshakeHash(recordData + offset, 4 + hsLen);
                    gotCertificateVerify = true;
                    break;
                }

                case TLS_HS_FINISHED: {
                    if (hsLen != 48) {
                        return false;
                    }

                    byte expectedVerify[48];
                    if (!computeFinishedVerify13(serverHsTrafficSecret, expectedVerify)) {
                        return false;
                    }

                    int diff = 0;
                    for (u32 i = 0; i < 48; i++) {
                        diff |= hsBody[i] ^ expectedVerify[i];
                    }
                    if (diff != 0) {
                        return false;
                    }

                    updateHandshakeHash(recordData + offset, 4 + hsLen);
                    gotFinished = true;
                    break;
                }

                default:
                    updateHandshakeHash(recordData + offset, 4 + hsLen);
                    break;
            }

            offset += 4 + hsLen;
        }
    }

    return gotEncryptedExtensions && gotCertificate && gotCertificateVerify && gotFinished;
    VMProtectEnd();
}

bool TlsSocket::performTlsHandshake() {
    VMProtectBeginMutation("TlsSocket_performTlsHandshake");

    if (!initHandshakeHash()) { return false; }

    if (!sendClientHello()) {
        if (clientEcdhPrivKey) { crypto->freeKeyHandle(clientEcdhPrivKey); clientEcdhPrivKey = nullptr; }
        return false;
    }

    byte serverEcdhPub[256];
    u32 serverEcdhPubLen = 0;
    if (!processServerMessages(serverEcdhPub, serverEcdhPubLen)) {
        if (clientEcdhPrivKey) { crypto->freeKeyHandle(clientEcdhPrivKey); clientEcdhPrivKey = nullptr; }
        return false;
    }

    if (isTls13) {
        if (serverEcdhPubLen != 65 || serverEcdhPub[0] != 0x04) {
            crypto->freeKeyHandle(clientEcdhPrivKey);
            clientEcdhPrivKey = nullptr;
            return false;
        }

        byte serverX509[91];
        static const byte x509Header[27] = {
            0x30, 0x59,
            0x30, 0x13,
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
            0x03, 0x42, 0x00,
            0x04
        };
        SyscallManager::SecureMemCpy(serverX509, x509Header, 27);
        SyscallManager::SecureMemCpy(serverX509 + 27, serverEcdhPub + 1, 64);

        byte sharedSecret[32];
        if (!crypto->deriveRawSecret(clientEcdhPrivKey, serverX509, 91, sharedSecret)) {
            crypto->freeKeyHandle(clientEcdhPrivKey);
            clientEcdhPrivKey = nullptr;
            return false;
        }
        crypto->freeKeyHandle(clientEcdhPrivKey);
        clientEcdhPrivKey = nullptr;

        if (!deriveHandshakeKeys(sharedSecret, 32)) {
            return false;
        }
        SyscallManager::SecureZero(sharedSecret, 32);

        handshakeKeysActive = true;
        cipherActive = true;
        hsClientSeqNum = 0;
        hsServerSeqNum = 0;

        if (!processEncryptedHandshakeMessages()) {
            return false;
        }

        if (!deriveApplicationKeys()) {
            return false;
        }

        serverSeqNum = 0;

        {
            byte ccsData = 1;
            byte header[5];
            header[0] = TLS_CONTENT_CHANGE_CIPHER;
            putU16BE(header + 1, TLS_VERSION_12);
            putU16BE(header + 3, 1);
            rawSocket.send(header, 5);
            rawSocket.send(&ccsData, 1);
        }

        if (!sendClientFinished13()) {
            return false;
        }

        clientSeqNum = 0;
        handshakeKeysActive = false;

        return true;

    } else {
        if (clientEcdhPrivKey) {
            crypto->freeKeyHandle(clientEcdhPrivKey);
            clientEcdhPrivKey = nullptr;
        }
        return false;
    }
    VMProtectEnd();
}

bool TlsSocket::sendClientHello() {
    VMProtectBeginMutation("TlsSocket_sendClientHello");
    crypto->generateRandomBytes(clientRandom, 32);

    byte clientEcdhPub[256];
    u32 clientEcdhPubLen = 0;
    if (!crypto->generateEcdhKeyPair(clientEcdhPub, &clientEcdhPubLen, &clientEcdhPrivKey)) {
        return false;
    }

    byte rawClientPub[65];
    rawClientPub[0] = 0x04;
    SyscallManager::SecureMemCpy(rawClientPub + 1, clientEcdhPub + 27, 64);

    byte msg[600];
    u32 pos = 0;

    u32 hsHeaderPos = pos;
    pos += 4;

    putU16BE(msg + pos, TLS_VERSION_12); pos += 2;
    SyscallManager::SecureMemCpy(msg + pos, clientRandom, 32); pos += 32;
    msg[pos++] = 0;

    putU16BE(msg + pos, 6); pos += 2;                 // 3 cipher suites = 6 bytes
    putU16BE(msg + pos, 0x1302); pos += 2;             // TLS_AES_256_GCM_SHA384 (TLS 1.3)
    putU16BE(msg + pos, 0xC02C); pos += 2;             // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    putU16BE(msg + pos, 0xC030); pos += 2;             // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

    msg[pos++] = 1;                                    // 1 method
    msg[pos++] = 0;                                    // null compression

    u32 extLenPos = pos;
    pos += 2; // extension list length (filled later)

    putU16BE(msg + pos, 0x000A); pos += 2;            // type
    putU16BE(msg + pos, 4); pos += 2;                 // extension data length
    putU16BE(msg + pos, 2); pos += 2;                 // named curve list length
    putU16BE(msg + pos, 0x0017); pos += 2;            // secp256r1

    putU16BE(msg + pos, 0x000B); pos += 2;            // type
    putU16BE(msg + pos, 2); pos += 2;                 // extension data length
    msg[pos++] = 1;                                    // ec_point_format list length
    msg[pos++] = 0;                                    // uncompressed

    putU16BE(msg + pos, 0x000D); pos += 2;            // type
    putU16BE(msg + pos, 10); pos += 2;                // extension data length
    putU16BE(msg + pos, 8); pos += 2;                 // algorithm list length
    putU16BE(msg + pos, 0x0403); pos += 2;            // ecdsa_secp256r1_sha256
    putU16BE(msg + pos, 0x0804); pos += 2;            // rsa_pss_rsae_sha256
    putU16BE(msg + pos, 0x0401); pos += 2;            // rsa_pkcs1_sha256
    putU16BE(msg + pos, 0x0501); pos += 2;            // rsa_pkcs1_sha384

    putU16BE(msg + pos, TLS_EXT_SUPPORTED_VERSIONS); pos += 2; // type 0x002B
    putU16BE(msg + pos, 3); pos += 2;                 // extension data length
    msg[pos++] = 2;                                    // supported versions list length (1 version * 2 bytes)
    putU16BE(msg + pos, TLS_VERSION_13); pos += 2;    // TLS 1.3 (0x0304)

    putU16BE(msg + pos, TLS_EXT_KEY_SHARE); pos += 2; // type 0x0033
    putU16BE(msg + pos, 2 + 2 + 2 + 65); pos += 2;   // extension data length = 71
    putU16BE(msg + pos, 2 + 2 + 65); pos += 2;        // client_shares length = 69
    putU16BE(msg + pos, 0x0017); pos += 2;            // named group: secp256r1
    putU16BE(msg + pos, 65); pos += 2;                // key_exchange length
    SyscallManager::SecureMemCpy(msg + pos, rawClientPub, 65); pos += 65;

    putU16BE(msg + extLenPos, (u16)(pos - extLenPos - 2));

    u32 bodyLen = pos - hsHeaderPos - 4;
    msg[hsHeaderPos] = TLS_HS_CLIENT_HELLO;
    putU24BE(msg + hsHeaderPos + 1, bodyLen);

    updateHandshakeHash(msg, pos);

    return sendRecord(TLS_CONTENT_HANDSHAKE, msg, pos);
    VMProtectEnd();
}

bool TlsSocket::processServerMessages(byte* serverEcdhPub, u32& serverEcdhPubLen) {
    VMProtectBeginMutation("TlsSocket_processServerMessages");
    bool gotServerHello = false;
    bool gotCertificate = false;
    bool gotServerKeyExchange = false;
    bool gotServerHelloDone = false;

    while (true) {
        byte contentType = 0;
        byte recordData[16384];
        u32 recordLen = 0;

        if (!recvRecord(contentType, recordData, recordLen, sizeof(recordData))) {
            return false;
        }

        if (isTls13 && contentType == TLS_CONTENT_CHANGE_CIPHER) {
            continue;
        }

        if (contentType != TLS_CONTENT_HANDSHAKE) {
            if (contentType == TLS_CONTENT_ALERT) {
            }
            return false;
        }

        u32 offset = 0;
        while (offset < recordLen) {
            if (offset + 4 > recordLen) { return false; }

            byte hsType = recordData[offset];
            u32 hsLen = getU24BE(recordData + offset + 1);

            if (offset + 4 + hsLen > recordLen) { return false; }

            byte* hsBody = recordData + offset + 4;

            updateHandshakeHash(recordData + offset, 4 + hsLen);

            switch (hsType) {
                case TLS_HS_SERVER_HELLO: {
                    if (hsLen < 38) { return false; }
                    SyscallManager::SecureMemCpy(serverRandom, hsBody + 2, 32);

                    u32 p = 34;
                    byte sessionIdLen = hsBody[p++];
                    p += sessionIdLen;

                    if (p + 2 > hsLen) { return false; }
                    u16 chosenCipher = getU16BE(hsBody + p); p += 2;

                    p++;

                    bool foundSupportedVersions13 = false;
                    if (p + 2 <= hsLen) {
                        u16 extTotalLen = getU16BE(hsBody + p);
                        p += 2;

                        u32 extEnd = p + extTotalLen;
                        if (extEnd > hsLen) extEnd = hsLen;

                        while (p + 4 <= extEnd) {
                            u16 extType = getU16BE(hsBody + p); p += 2;
                            u16 extLen = getU16BE(hsBody + p); p += 2;

                            if (p + extLen > extEnd) break;

                            if (extType == TLS_EXT_SUPPORTED_VERSIONS && extLen >= 2) {
                                u16 selectedVersion = getU16BE(hsBody + p);
                                if (selectedVersion == TLS_VERSION_13) {
                                    foundSupportedVersions13 = true;
                                }
                            } else if (extType == TLS_EXT_KEY_SHARE && extLen >= 4) {
                                u16 group = getU16BE(hsBody + p);
                                u16 keyExLen = getU16BE(hsBody + p + 2);
                                if (group == 0x0017 && keyExLen == 65 && p + 4 + 65 <= extEnd) {
                                    SyscallManager::SecureMemCpy(serverEcdhPub, hsBody + p + 4, 65);
                                    serverEcdhPubLen = 65;
                                }
                            }

                            p += extLen;
                        }
                    }

                    if (foundSupportedVersions13 && chosenCipher == TLS_CIPHER_AES_256_GCM_SHA384) {
                        isTls13 = true;
                        negotiatedCipher = chosenCipher;
                        gotServerHello = true;
                        return true;
                    }

                    return false;

#if 0
                    // Downgrade protection: check last 8 bytes of serverRandom
                    static const byte downgradeSentinel[] = { 'D','O','W','N','G','R','D', 0x01 };
                    bool isDowngrade = true;
                    for (int i = 0; i < 8; i++) {
                        if (serverRandom[24 + i] != downgradeSentinel[i]) {
                            isDowngrade = false;
                            break;
                        }
                    }
                    if (isDowngrade) {
                        _TlsDbg("[TlsSocket] Downgrade sentinel detected in serverRandom\n");
                        return false;
                    }

                    // Accept TLS 1.2 cipher suites
                    if (chosenCipher != 0xC02C && chosenCipher != 0xC030) {
                        _TlsDbg("[TlsSocket] Server chose unsupported cipher suite\n");
                        return false;
                    }
                    negotiatedCipher = chosenCipher;

                    gotServerHello = true;
                    _TlsDbg("[TlsSocket] Got ServerHello (TLS 1.2)\n");
                    break;
#endif
                }

                case TLS_HS_CERTIFICATE: {
                    if (hsLen < 3) { return false; }
                    u32 certsLen = getU24BE(hsBody);
                    if (3 + certsLen > hsLen) { return false; }
                    if (certsLen < 3) { return false; }

                    u32 certLen = getU24BE(hsBody + 3);
                    if (6 + certLen > 3 + certsLen) { return false; }
                    const byte* certData = hsBody + 6;

                    if (certLen <= sizeof(serverCertDer)) {
                        SyscallManager::SecureMemCpy(serverCertDer, certData, certLen);
                        serverCertDerLen = certLen;
                    }

                    static const byte ecP256Oid[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
                    static const byte rsaOid[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

                    serverCertPubKeyLen = 0;
                    for (u32 i = 0; i + 10 < certLen; i++) {
                        if (certData[i] != 0x30) continue;

                        u32 seqStart = i;
                        u32 li = i + 1;
                        u32 seqContentLen = 0;
                        u32 headerSize = 2;
                        if (certData[li] < 0x80) {
                            seqContentLen = certData[li];
                        } else if (certData[li] == 0x81 && li + 1 < certLen) {
                            seqContentLen = certData[li + 1];
                            headerSize = 3;
                        } else if (certData[li] == 0x82 && li + 2 < certLen) {
                            seqContentLen = ((u32)certData[li + 1] << 8) | certData[li + 2];
                            headerSize = 4;
                        } else {
                            continue;
                        }

                        u32 seqTotalLen = headerSize + seqContentLen;
                        if (seqStart + seqTotalLen > certLen) continue;

                        const byte* seqContent = certData + seqStart + headerSize;
                        bool isEc = false;
                        bool isRsa = false;
                        for (u32 j = 0; j + 10 <= seqContentLen; j++) {
                            if (!isEc && j + 10 <= seqContentLen) {
                                bool match = true;
                                for (u32 k = 0; k < 10; k++) {
                                    if (seqContent[j + k] != ecP256Oid[k]) { match = false; break; }
                                }
                                if (match) isEc = true;
                            }
                            if (!isRsa && j + 11 <= seqContentLen) {
                                bool match = true;
                                for (u32 k = 0; k < 11; k++) {
                                    if (seqContent[j + k] != rsaOid[k]) { match = false; break; }
                                }
                                if (match) isRsa = true;
                            }
                        }

                        if (isEc || isRsa) {
                            if (seqTotalLen <= sizeof(serverCertPubKey)) {
                                SyscallManager::SecureMemCpy(serverCertPubKey, certData + seqStart, seqTotalLen);
                                serverCertPubKeyLen = seqTotalLen;
                                break;
                            }
                        }
                    }

                    if (serverCertPubKeyLen == 0) {
                        return false;
                    }

                    if (!validateSelfSignedCert(certData, certLen)) {
                        return false;
                    }

                    gotCertificate = true;
                    break;
                }

                case TLS_HS_SERVER_KEY_EXCHANGE: {
                    if (hsLen < 4) { return false; }

                    byte curveType = hsBody[0];
                    u16 namedCurve = getU16BE(hsBody + 1);
                    byte pubKeyLen = hsBody[3];

                    if (curveType != 0x03 || namedCurve != 0x0017) {
                        return false;
                    }

                    if (4 + pubKeyLen > hsLen) { return false; }
                    if (pubKeyLen > 255) { return false; }

                    SyscallManager::SecureMemCpy(serverEcdhPub, hsBody + 4, pubKeyLen);
                    serverEcdhPubLen = pubKeyLen;

                    if (!verifyServerKeyExchangeSignature(hsBody, hsLen, pubKeyLen)) {
                        return false;
                    }

                    gotServerKeyExchange = true;
                    break;
                }

                case TLS_HS_SERVER_HELLO_DONE: {
                    gotServerHelloDone = true;
                    break;
                }

                default:
                    break;
            }

            offset += 4 + hsLen;
        }

        if (!isTls13 && gotServerHelloDone) {
            return false;
        }
    }

    return gotServerHello && gotCertificate && gotServerKeyExchange && gotServerHelloDone;
    VMProtectEnd();
}

bool TlsSocket::sendClientKeyExchange(const byte* serverEcdhPub, u32 pubLen) {
    VMProtectBeginUltra("TlsSocket_sendClientKeyExchange");
    byte clientPub[256];
    u32 clientPubLen = 0;
    void* clientPrivKey = nullptr;

    if (!crypto->generateEcdhKeyPair(clientPub, &clientPubLen, &clientPrivKey)) {
        return false;
    }

    byte serverX509[91];
    if (pubLen != 65 || serverEcdhPub[0] != 0x04) {
        crypto->freeKeyHandle(clientPrivKey);
        return false;
    }

    static const byte x509Header[27] = {
        0x30, 0x59,
        0x30, 0x13,
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00,
        0x04
    };
    SyscallManager::SecureMemCpy(serverX509, x509Header, 27);
    SyscallManager::SecureMemCpy(serverX509 + 27, serverEcdhPub + 1, 64); // X + Y

    byte preMasterSecret[32];
    if (!crypto->deriveRawSecret(clientPrivKey, serverX509, 91, preMasterSecret)) {
        crypto->freeKeyHandle(clientPrivKey);
        return false;
    }
    crypto->freeKeyHandle(clientPrivKey);

    byte rawClientPub[65];
    rawClientPub[0] = 0x04; // uncompressed
    SyscallManager::SecureMemCpy(rawClientPub + 1, clientPub + 27, 64); // X + Y from X.509

    byte msg[128];
    u32 pos = 0;

    msg[pos++] = TLS_HS_CLIENT_KEY_EXCHANGE;
    putU24BE(msg + pos, 1 + 65); pos += 3; // length = 1 + 65

    msg[pos++] = 65;
    SyscallManager::SecureMemCpy(msg + pos, rawClientPub, 65); pos += 65;

    updateHandshakeHash(msg, pos);

    if (!sendRecord(TLS_CONTENT_HANDSHAKE, msg, pos)) {
        return false;
    }

    byte seed[64];
    SyscallManager::SecureMemCpy(seed, clientRandom, 32);
    SyscallManager::SecureMemCpy(seed + 32, serverRandom, 32);

    if (!prf(preMasterSecret, 32, "master secret", seed, 64, masterSecret, 48)) {
        return false;
    }

    SyscallManager::SecureZero(preMasterSecret, 32);

    return deriveKeys();
    VMProtectEnd();
}

bool TlsSocket::deriveKeys() {
    VMProtectBeginMutation("TlsSocket_deriveKeys");
    byte seed[64];
    SyscallManager::SecureMemCpy(seed, serverRandom, 32);
    SyscallManager::SecureMemCpy(seed + 32, clientRandom, 32);

    byte keyBlock[72];
    if (!prf(masterSecret, 48, "key expansion", seed, 64, keyBlock, 72)) {
        return false;
    }

    SyscallManager::SecureMemCpy(clientWriteKey, keyBlock, 32);
    SyscallManager::SecureMemCpy(serverWriteKey, keyBlock + 32, 32);
    SyscallManager::SecureMemCpy(clientWriteIV, keyBlock + 64, 4);
    SyscallManager::SecureMemCpy(serverWriteIV, keyBlock + 68, 4);

    SyscallManager::SecureZero(keyBlock, 72);
    return true;
    VMProtectEnd();
}

bool TlsSocket::sendChangeCipherSpec() {
    VMProtectBeginMutation("TlsSocket_sendChangeCipherSpec");
    byte ccs = 1;
    if (!sendRecord(TLS_CONTENT_CHANGE_CIPHER, &ccs, 1)) {
        return false;
    }
    cipherActive = true;
    clientSeqNum = 0;
    return true;
    VMProtectEnd();
}

bool TlsSocket::sendFinished() {
    VMProtectBeginMutation("TlsSocket_sendFinished");
    byte hsHash[48];
    if (!getHandshakeHash(hsHash)) { return false; }

    byte verifyData[12];
    if (!prf(masterSecret, 48, "client finished", hsHash, 48, verifyData, 12)) {
        return false;
    }

    byte msg[16];
    msg[0] = TLS_HS_FINISHED;
    putU24BE(msg + 1, 12);
    SyscallManager::SecureMemCpy(msg + 4, verifyData, 12);

    updateHandshakeHash(msg, 16);

    return sendRecord(TLS_CONTENT_HANDSHAKE, msg, 16);
    VMProtectEnd();
}

bool TlsSocket::recvServerChangeCipherSpecAndFinished() {
    VMProtectBeginMutation("TlsSocket_recvServerChangeCipherSpecAndFinished");
    byte contentType = 0;
    byte recordData[256];
    u32 recordLen = 0;

    if (!recvRecord(contentType, recordData, recordLen, sizeof(recordData))) {
        return false;
    }

    if (contentType != TLS_CONTENT_CHANGE_CIPHER || recordLen != 1 || recordData[0] != 1) {
        return false;
    }

    serverSeqNum = 0;

    if (!recvRecord(contentType, recordData, recordLen, sizeof(recordData))) {
        return false;
    }

    if (contentType != TLS_CONTENT_HANDSHAKE) {
        return false;
    }

    if (recordLen < 16) { return false; } // type(1) + len(3) + verify_data(12)
    if (recordData[0] != TLS_HS_FINISHED) { return false; }

    u32 finishedLen = getU24BE(recordData + 1);
    if (finishedLen != 12) { return false; }

    byte hsHash[48];
    if (!getHandshakeHash(hsHash)) { return false; }

    byte expectedVerify[12];
    if (!prf(masterSecret, 48, "server finished", hsHash, 48, expectedVerify, 12)) {
        return false;
    }

    int diff = 0;
    for (int i = 0; i < 12; i++) {
        diff |= recordData[4 + i] ^ expectedVerify[i];
    }
    if (diff != 0) {
        return false;
    }

    return true;
    VMProtectEnd();
}

bool TlsSocket::initHandshakeHash() {
    VMProtectBeginUltra("TlsSocket_initHandshakeHash");
    DWORD objLen = 0;
    ULONG result = 0;
    BCryptGetProperty(hSha384, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &result, 0);

    handshakeHash = new byte[objLen];
    NTSTATUS s = BCryptCreateHash(hSha384, &hHandshakeHash, handshakeHash, objLen, nullptr, 0, 0);
    return BCRYPT_SUCCESS(s);
    VMProtectEnd();
}

bool TlsSocket::updateHandshakeHash(const byte* data, u32 len) {
    VMProtectBeginUltra("TlsSocket_updateHandshakeHash");
    if (!hHandshakeHash) { return false; }
    NTSTATUS s = BCryptHashData(hHandshakeHash, (PUCHAR)data, len, 0);
    return BCRYPT_SUCCESS(s);
    VMProtectEnd();
}

bool TlsSocket::getHandshakeHash(byte* hashOut) {
    VMProtectBeginUltra("TlsSocket_getHandshakeHash");
    if (!hHandshakeHash) { return false; }

    BCRYPT_HASH_HANDLE hDup = nullptr;
    NTSTATUS s = BCryptDuplicateHash(hHandshakeHash, &hDup, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(s)) { return false; }

    s = BCryptFinishHash(hDup, hashOut, 48, 0);
    BCryptDestroyHash(hDup);
    return BCRYPT_SUCCESS(s);
    VMProtectEnd();
}

bool TlsSocket::finalizeHandshakeHash(byte* hashOut) {
    VMProtectBeginUltra("TlsSocket_finalizeHandshakeHash");
    if (!hHandshakeHash) { return false; }
    NTSTATUS s = BCryptFinishHash(hHandshakeHash, hashOut, 48, 0);
    hHandshakeHash = nullptr;
    bool result = BCRYPT_SUCCESS(s);
    return result;
    VMProtectEnd();
}

bool TlsSocket::hmacSha384(const byte* key, u32 keyLen,
                            const byte* data, u32 dataLen,
                            byte* out) {
    VMProtectBeginMutation("TlsSocket_hmacSha384");
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS s = BCryptCreateHash(hHmacSha384, &hHash, nullptr, 0,
                                   (PUCHAR)key, keyLen, BCRYPT_HASH_REUSABLE_FLAG);
    if (!BCRYPT_SUCCESS(s)) { return false; }

    s = BCryptHashData(hHash, (PUCHAR)data, dataLen, 0);
    if (!BCRYPT_SUCCESS(s)) { BCryptDestroyHash(hHash); return false; }

    s = BCryptFinishHash(hHash, out, 48, 0);
    BCryptDestroyHash(hHash);
    return BCRYPT_SUCCESS(s);
    VMProtectEnd();
}

bool TlsSocket::prf(const byte* secret, u32 secretLen,
                     const char* label,
                     const byte* seed, u32 seedLen,
                     byte* output, u32 outputLen) {
    VMProtectBeginMutation("TlsSocket_prf");
    u32 labelLen = 0;
    const char* p = label;
    while (*p) { labelLen++; p++; }

    u32 lsLen = labelLen + seedLen;
    byte* labelSeed = new byte[lsLen];
    SyscallManager::SecureMemCpy(labelSeed, label, labelLen);
    SyscallManager::SecureMemCpy(labelSeed + labelLen, seed, seedLen);

    byte a[48]; // A(i) — 48 bytes for SHA-384
    if (!hmacSha384(secret, secretLen, labelSeed, lsLen, a)) {
        delete[] labelSeed;
        return false;
    }

    u32 generated = 0;
    byte* concat = new byte[48 + lsLen]; // A(i) + label+seed

    while (generated < outputLen) {
        SyscallManager::SecureMemCpy(concat, a, 48);
        SyscallManager::SecureMemCpy(concat + 48, labelSeed, lsLen);

        byte block[48];
        if (!hmacSha384(secret, secretLen, concat, 48 + lsLen, block)) {
            delete[] labelSeed;
            delete[] concat;
            return false;
        }

        u32 copyLen = outputLen - generated;
        if (copyLen > 48) copyLen = 48;
        SyscallManager::SecureMemCpy(output + generated, block, copyLen);
        generated += copyLen;

        byte aNext[48];
        if (!hmacSha384(secret, secretLen, a, 48, aNext)) {
            delete[] labelSeed;
            delete[] concat;
            return false;
        }
        SyscallManager::SecureMemCpy(a, aNext, 48);
    }

    delete[] labelSeed;
    delete[] concat;
    return true;
    VMProtectEnd();
}

bool TlsSocket::verifyServerKeyExchangeSignature(const byte* hsBody, u32 hsLen,
                                                   byte pubKeyLen) {
    VMProtectBeginMutation("TlsSocket_verifyServerKeyExchangeSignature");
    u32 paramsLen = 4 + pubKeyLen;
    if (paramsLen + 4 > hsLen) {
        return false;
    }

    byte hashAlg = hsBody[paramsLen];
    byte sigAlg = hsBody[paramsLen + 1];
    u16 sigLen = getU16BE(hsBody + paramsLen + 2);

    if (paramsLen + 4 + sigLen > hsLen) {
        return false;
    }

    const byte* signature = hsBody + paramsLen + 4;

    u32 signedDataLen = 32 + 32 + paramsLen;
    byte* signedData = new byte[signedDataLen];
    SyscallManager::SecureMemCpy(signedData, clientRandom, 32);
    SyscallManager::SecureMemCpy(signedData + 32, serverRandom, 32);
    SyscallManager::SecureMemCpy(signedData + 64, hsBody, paramsLen);

    byte hash[32];
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS s = BCryptCreateHash(hSha256, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(s)) {
        delete[] signedData;
        return false;
    }
    BCryptHashData(hHash, (PUCHAR)signedData, signedDataLen, 0);
    BCryptFinishHash(hHash, hash, 32, 0);
    BCryptDestroyHash(hHash);
    delete[] signedData;

    if (sigAlg == 3) {
        if (crypto->verifyEcdsa(serverCertPubKey, serverCertPubKeyLen,
                                 hash, 32, signature, sigLen, true)) {
            return true;
        }
        return false;
    }

    if (sigAlg == 1) {
        BCRYPT_KEY_HANDLE hRsaKey = nullptr;

        CERT_PUBLIC_KEY_INFO* pubKeyInfo = nullptr;
        DWORD pubKeyInfoLen = 0;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                                  serverCertPubKey, serverCertPubKeyLen,
                                  CRYPT_DECODE_ALLOC_FLAG, nullptr,
                                  &pubKeyInfo, &pubKeyInfoLen)) {
            return false;
        }

        if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pubKeyInfo, 0, nullptr, &hRsaKey)) {
            LocalFree(pubKeyInfo);
            return false;
        }
        LocalFree(pubKeyInfo);

        BCRYPT_PKCS1_PADDING_INFO paddingInfo;
        paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

        s = BCryptVerifySignature(hRsaKey, &paddingInfo,
                                   hash, 32,
                                   (PUCHAR)signature, sigLen,
                                   BCRYPT_PAD_PKCS1);

        BCryptDestroyKey(hRsaKey);

        if (BCRYPT_SUCCESS(s)) {
            return true;
        }
        return false;
    }

    return false;
}

bool TlsSocket::aesGcmEncrypt(const byte* key, const byte* nonce,
                                const byte* aad, u32 aadLen,
                                const byte* plaintext, u32 plaintextLen,
                                byte* ciphertext, byte* tag) {
    // VMProtect removed - called ~433 times per 6 MB transfer (hot path, causes 0.72s delay per call)
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS s = BCryptGenerateSymmetricKey(hAesGcm, &hKey, nullptr, 0,
                                             (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(s)) { return false; }

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
}

bool TlsSocket::aesGcmDecrypt(const byte* key, const byte* nonce,
                                const byte* aad, u32 aadLen,
                                const byte* ciphertext, u32 ciphertextLen,
                                const byte* tag,
                                byte* plaintext) {
    static BCRYPT_KEY_HANDLE cachedKey = nullptr;
    static byte cachedKeyData[32];

    if (!cachedKey || SyscallManager::SecureMemCmp(cachedKeyData, key, 32) != 0) {
        if (cachedKey) BCryptDestroyKey(cachedKey);
        if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAesGcm, &cachedKey, nullptr, 0, (PUCHAR)key, 32, 0))) {
            return false;
        }
        SyscallManager::SecureMemCpy(cachedKeyData, key, 32);
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = 12;
    authInfo.pbAuthData = (PUCHAR)aad;
    authInfo.cbAuthData = aadLen;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = 16;

    DWORD cbResult = 0;
    return BCRYPT_SUCCESS(BCryptDecrypt(cachedKey, (PUCHAR)ciphertext, ciphertextLen, &authInfo, nullptr, 0,
                                        plaintext, ciphertextLen, &cbResult, 0));
}

void* TlsSocket::decryptTaskEntry(void* param) {
    DecryptTask* task = (DecryptTask*)param;
    char buf[256];

    sprintf_s(buf, "[Worker] Thread started, ciphertextLen=%u, plaintext=%p\n", task->ciphertextLen, task->plaintext);

    BCRYPT_ALG_HANDLE hLocal = nullptr;
    BCryptOpenAlgorithmProvider(&hLocal, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(hLocal, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS s = BCryptGenerateSymmetricKey(hLocal, &hKey, nullptr, 0,
                                             (PUCHAR)task->key, 32, 0);
    if (BCRYPT_SUCCESS(s)) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)task->nonce;
        authInfo.cbNonce = 12;
        authInfo.pbAuthData = (PUCHAR)task->aad;
        authInfo.cbAuthData = task->aadLen;
        authInfo.pbTag = (PUCHAR)task->tag;
        authInfo.cbTag = 16;

        DWORD cbResult = 0;
        s = BCryptDecrypt(hKey, (PUCHAR)task->ciphertext, task->ciphertextLen,
                         &authInfo, nullptr, 0, (PUCHAR)task->plaintext, task->ciphertextLen,
                         &cbResult, 0);
        task->success = BCRYPT_SUCCESS(s);


        BCryptDestroyKey(hKey);
    } else {
        task->success = false;
    }

    if (hLocal) {
        BCryptCloseAlgorithmProvider(hLocal, 0);
    }

    task->complete = true;
    return nullptr;
}
