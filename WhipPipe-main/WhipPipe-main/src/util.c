#include "whippipe_internal.h"
#include <string.h>

int whipRecvExact(SOCKET sock, void* buf, unsigned int count)
{
    unsigned int offset = 0;
    while (offset < count)
    {
        int toRead = (count - offset > INT_MAX) ? INT_MAX : (int)(count - offset);
        int n = recv(sock, (char*)buf + offset, toRead, 0);
        if (n <= 0) return 0;
        offset += (unsigned int)n;
    }
    return 1;
}

int whipSendExact(SOCKET sock, const void* buf, unsigned int count)
{
    unsigned int offset = 0;
    while (offset < count)
    {
        int toSend = (count - offset > INT_MAX) ? INT_MAX : (int)(count - offset);
        int n = send(sock, (const char*)buf + offset, toSend, 0);
        if (n <= 0) return 0;
        offset += (unsigned int)n;
    }
    return 1;
}

int whipWaitReadable(SOCKET sock, int timeoutMs)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    struct timeval tv;
    tv.tv_sec  = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    return select(0, &fds, NULL, NULL, &tv) > 0;
}

void whipStrcpySafe(char* dst, const char* src, unsigned int dstSize)
{
    if (!dst || !src || dstSize == 0) return;

    unsigned int i = 0;
    while (i < dstSize - 1 && src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

// ─── Handshake challenge-response (raw, AVANT protocole chiffré) ─────────────

int whipLoaderHandshake(SOCKET sock, whip_crypto_ctx** cryptoOut, unsigned char* privkey, unsigned char* challenge)
{
    unsigned char pubkey[WHIP_ECDH_PUBKEY_SIZE];
    if (!whip_ecdh_generate_keypair(pubkey, privkey))
        return 0;

    if (!whip_random_bytes(challenge, WHIP_CHALLENGE_SIZE))
        return 0;

    unsigned char handshakeSend[96];
    memcpy(handshakeSend, pubkey, 64);
    memcpy(handshakeSend + 64, challenge, 32);

    if (!whipSendExact(sock, handshakeSend, 96))
        return 0;

    unsigned char handshakeRecv[96];
    if (!whipRecvExact(sock, handshakeRecv, 96))
        return 0;

    unsigned char* theirPubkey = handshakeRecv;
    unsigned char* theirResponse = handshakeRecv + 64;

    unsigned char sharedSecret[WHIP_SHARED_SECRET_SIZE];
    if (!whip_ecdh_compute_shared(theirPubkey, privkey, sharedSecret))
        return 0;

    unsigned char expectedResponse[WHIP_RESPONSE_SIZE];
    if (!whip_hmac_sha256(sharedSecret, WHIP_SHARED_SECRET_SIZE, challenge, WHIP_CHALLENGE_SIZE, expectedResponse))
        return 0;

    if (memcmp(theirResponse, expectedResponse, WHIP_RESPONSE_SIZE) != 0) {
        SecureZeroMemory(sharedSecret, sizeof(sharedSecret));
        return 0;
    }

    unsigned char sessionKey[WHIP_SESSION_KEY_SIZE];
    if (!whip_derive_session_key(sharedSecret, challenge, sessionKey)) {
        SecureZeroMemory(sharedSecret, sizeof(sharedSecret));
        return 0;
    }

    SecureZeroMemory(sharedSecret, sizeof(sharedSecret));

    *cryptoOut = whip_crypto_session_create(sessionKey);
    SecureZeroMemory(sessionKey, sizeof(sessionKey));

    return (*cryptoOut != NULL);
}

int whipClientHandshake(SOCKET sock, whip_crypto_ctx** cryptoOut, unsigned char* privkey)
{
    unsigned char handshakeRecv[96];
    if (!whipRecvExact(sock, handshakeRecv, 96))
        return 0;

    unsigned char* loaderPubkey = handshakeRecv;
    unsigned char* challenge = handshakeRecv + 64;

    unsigned char pubkey[WHIP_ECDH_PUBKEY_SIZE];
    if (!whip_ecdh_generate_keypair(pubkey, privkey))
        return 0;

    unsigned char sharedSecret[WHIP_SHARED_SECRET_SIZE];
    if (!whip_ecdh_compute_shared(loaderPubkey, privkey, sharedSecret))
        return 0;

    unsigned char response[WHIP_RESPONSE_SIZE];
    if (!whip_hmac_sha256(sharedSecret, WHIP_SHARED_SECRET_SIZE, challenge, WHIP_CHALLENGE_SIZE, response)) {
        SecureZeroMemory(sharedSecret, sizeof(sharedSecret));
        return 0;
    }

    unsigned char handshakeSend[96];
    memcpy(handshakeSend, pubkey, 64);
    memcpy(handshakeSend + 64, response, 32);

    if (!whipSendExact(sock, handshakeSend, 96)) {
        SecureZeroMemory(sharedSecret, sizeof(sharedSecret));
        return 0;
    }

    unsigned char sessionKey[WHIP_SESSION_KEY_SIZE];
    if (!whip_derive_session_key(sharedSecret, challenge, sessionKey)) {
        SecureZeroMemory(sharedSecret, sizeof(sharedSecret));
        return 0;
    }

    SecureZeroMemory(sharedSecret, sizeof(sharedSecret));

    *cryptoOut = whip_crypto_session_create(sessionKey);
    SecureZeroMemory(sessionKey, sizeof(sessionKey));

    return (*cryptoOut != NULL);
}

// ─── Protocole typé CHIFFRÉ ──────────────────────────────────────────────────

int whipSendMessage(SOCKET sock, whip_crypto_ctx* crypto, WhipMessageType type, const unsigned char* data, unsigned int len)
{
    if (!crypto) return 0;

    unsigned int plaintextLen = 1 + len;
    unsigned char* plaintext = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, plaintextLen);
    if (!plaintext) return 0;

    plaintext[0] = (unsigned char)type;
    if (len > 0 && data)
        memcpy(plaintext + 1, data, len);

    unsigned char nonce[WHIP_NONCE_SIZE];
    unsigned char* ciphertext = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, plaintextLen);
    unsigned char mac[WHIP_MAC_SIZE];

    if (!ciphertext) {
        HeapFree(GetProcessHeap(), 0, plaintext);
        return 0;
    }

    if (!whip_encrypt_message(crypto, plaintext, plaintextLen, nonce, ciphertext, mac)) {
        HeapFree(GetProcessHeap(), 0, plaintext);
        HeapFree(GetProcessHeap(), 0, ciphertext);
        return 0;
    }

    SecureZeroMemory(plaintext, plaintextLen);
    HeapFree(GetProcessHeap(), 0, plaintext);

    unsigned int wireLen = plaintextLen + WHIP_NONCE_SIZE + WHIP_MAC_SIZE;
    unsigned int header = wireLen;

    if (!whipSendExact(sock, &header, sizeof header))
        goto fail;
    if (!whipSendExact(sock, nonce, WHIP_NONCE_SIZE))
        goto fail;
    if (!whipSendExact(sock, ciphertext, plaintextLen))
        goto fail;
    if (!whipSendExact(sock, mac, WHIP_MAC_SIZE))
        goto fail;

    HeapFree(GetProcessHeap(), 0, ciphertext);
    return 1;

fail:
    HeapFree(GetProcessHeap(), 0, ciphertext);
    return 0;
}

int whipRecvMessage(SOCKET sock, whip_crypto_ctx* crypto, WhipMessage* outMsg)
{
    if (!outMsg || !crypto) return 0;

    unsigned int wireLen = 0;
    if (!whipRecvExact(sock, &wireLen, sizeof wireLen))
        return 0;

    if (wireLen < WHIP_NONCE_SIZE + 1 + WHIP_MAC_SIZE)
        return 0;

    unsigned int ciphertextLen = wireLen - WHIP_NONCE_SIZE - WHIP_MAC_SIZE;

    unsigned char nonce[WHIP_NONCE_SIZE];
    unsigned char* ciphertext = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, ciphertextLen);
    unsigned char mac[WHIP_MAC_SIZE];

    if (!ciphertext) return 0;

    if (!whipRecvExact(sock, nonce, WHIP_NONCE_SIZE))
        goto fail;
    if (!whipRecvExact(sock, ciphertext, ciphertextLen))
        goto fail;
    if (!whipRecvExact(sock, mac, WHIP_MAC_SIZE))
        goto fail;

    unsigned char* plaintext = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, ciphertextLen);
    if (!plaintext) goto fail;

    if (!whip_decrypt_message(crypto, nonce, ciphertext, ciphertextLen, mac, plaintext)) {
        HeapFree(GetProcessHeap(), 0, plaintext);
        goto fail;
    }

    HeapFree(GetProcessHeap(), 0, ciphertext);

    if (ciphertextLen < 1) {
        HeapFree(GetProcessHeap(), 0, plaintext);
        return 0;
    }

    outMsg->type = (WhipMessageType)plaintext[0];

    unsigned int payloadLen = ciphertextLen - 1;
    if (payloadLen == 0) {
        outMsg->data = NULL;
        outMsg->len  = 0;
        HeapFree(GetProcessHeap(), 0, plaintext);
        return 1;
    }

    unsigned char* payload = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, payloadLen);
    if (!payload) {
        HeapFree(GetProcessHeap(), 0, plaintext);
        return 0;
    }

    memcpy(payload, plaintext + 1, payloadLen);
    SecureZeroMemory(plaintext, ciphertextLen);
    HeapFree(GetProcessHeap(), 0, plaintext);

    outMsg->data = payload;
    outMsg->len  = payloadLen;
    return 1;

fail:
    HeapFree(GetProcessHeap(), 0, ciphertext);
    return 0;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const char* whipMessageTypeStr(WhipMessageType type)
{
    switch (type) {
        case IpcReady:  return "IpcReady";
        case IpcStatus: return "IpcStatus";
        case IpcError:  return "IpcError";
        case IpcUnload: return "IpcUnload";
        case IpcConfig: return "IpcConfig";
        case IpcPing:   return "IpcPing";
        case IpcPong:   return "IpcPong";
        default:        return "IpcCustom";
    }
}