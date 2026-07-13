#ifndef WHIPNEXUS_TLSSERVERCONTEXT_H
#define WHIPNEXUS_TLSSERVERCONTEXT_H

#include "Types.h"
#include "CryptoService.h"
#include <windows.h>
#include <bcrypt.h>

class SyscallResolver;

// Per-client TLS 1.2 server-side context.
// Wraps a raw HANDLE (from TcpServerSocket::accept()) and provides
// encrypted send/receive matching what TlsSocket (client) expects.
// Cipher suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)
class TlsServerContext {
private:
    HANDLE          rawSocket;       // NOT owned; caller manages lifetime
    SyscallResolver* resolver;
    CryptoService*  crypto;

    // BCrypt algorithm handles (opened per context)
    BCRYPT_ALG_HANDLE hAesGcm;
    BCRYPT_ALG_HANDLE hSha256;
    BCRYPT_ALG_HANDLE hHmacSha256;

    // TLS handshake state
    byte clientRandom[32];
    byte serverRandom[32];
    byte masterSecret[48];

    // Traffic keys (AES-128-GCM, matches TlsSocket layout)
    byte clientWriteKey[16];   // client->server (decryption for us)
    byte serverWriteKey[16];   // server->client (encryption for us)
    byte clientWriteIV[4];
    byte serverWriteIV[4];

    // Sequence numbers
    u64 clientSeqNum;   // for decrypting client records
    u64 serverSeqNum;   // for encrypting server records

    // Handshake transcript hash (SHA-256)
    byte* handshakeHashObj;
    BCRYPT_HASH_HANDLE hHandshakeHash;

    // State flags
    bool tlsEstablished;
    bool cipherActive;          // true after server sends ChangeCipherSpec
    bool clientCipherActive;    // true after receiving client ChangeCipherSpec

    // Receive buffer for decrypted application data
    static const u32 RECV_BUF_SIZE = 32768;
    byte recvBuf[RECV_BUF_SIZE];
    u32 recvBufStart;
    u32 recvBufLen;

    // Raw receive buffer for TLS records
    static const u32 RAW_BUF_SIZE = 18432;
    byte rawRecvBuf[RAW_BUF_SIZE];

    // Server identity (NOT owned; shared across all clients)
    const byte* serverCertDer;
    u32         serverCertDerLen;
    void*       ecdsaPrivateKey;

    // TLS constants
    static const byte TLS_CONTENT_CHANGE_CIPHER = 20;
    static const byte TLS_CONTENT_ALERT         = 21;
    static const byte TLS_CONTENT_HANDSHAKE     = 22;
    static const byte TLS_CONTENT_APPLICATION   = 23;

    static const byte TLS_HS_CLIENT_HELLO       = 1;
    static const byte TLS_HS_SERVER_HELLO       = 2;
    static const byte TLS_HS_CERTIFICATE        = 11;
    static const byte TLS_HS_SERVER_KEY_EXCHANGE = 12;
    static const byte TLS_HS_SERVER_HELLO_DONE  = 14;
    static const byte TLS_HS_CLIENT_KEY_EXCHANGE = 16;
    static const byte TLS_HS_FINISHED           = 20;

    static const u16 TLS_VERSION_12 = 0x0303;
    static const u16 TLS_CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256 = 0xC02B;
    static const u16 TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256   = 0xC02F;

public:
    TlsServerContext();
    ~TlsServerContext();

    // Initialize with raw socket, resolver, crypto, and shared server cert/key
    void init(HANDLE socket, SyscallResolver* res, CryptoService* cryptoSvc,
              const byte* certDer, u32 certDerLen, void* ecdsaPrivKey);

    // Perform TLS handshake (blocking). Returns true on success.
    bool performHandshake();

    // Send application data (encrypts into TLS records)
    bool send(const byte* data, u32 length);

    // Receive application data (decrypts TLS records)
    i32 receive(byte* buffer, u32 bufferSize);
    bool receiveExact(byte* buffer, u32 length);

    bool isEstablished() const { return tlsEstablished; }

    void shutdown();

private:
    bool initAlgorithms();
    void cleanupAlgorithms();

    // Raw I/O on the HANDLE via AfdSocket
    bool rawSend(const byte* data, u32 len);
    bool rawRecvExact(byte* buf, u32 len);

    // TLS Record Layer
    bool sendRecord(byte contentType, const byte* data, u32 len);
    bool recvRecord(byte& contentType, byte* data, u32& len, u32 maxLen);

    // Server-side handshake steps
    bool recvClientHello(u16& chosenCipher);
    bool sendServerHello(u16 cipherSuite);
    bool sendCertificate();
    bool sendServerKeyExchange(const byte* ecdhPubRaw, u32 ecdhPubRawLen);
    bool sendServerHelloDone();
    bool recvClientKeyExchange(byte* clientEcdhPub, u32& clientEcdhPubLen);
    bool recvClientChangeCipherSpecAndFinished();
    bool sendChangeCipherSpec();
    bool sendFinished();

    // Handshake transcript
    bool initHandshakeHash();
    bool updateHandshakeHash(const byte* data, u32 len);
    bool getHandshakeHash(byte* hashOut);

    // TLS PRF (P_SHA256 for TLS 1.2)
    bool prf(const byte* secret, u32 secretLen, const char* label,
             const byte* seed, u32 seedLen, byte* output, u32 outputLen);
    bool hmacSha256(const byte* key, u32 keyLen,
                    const byte* data, u32 dataLen, byte* out);
    bool deriveKeys();

    // AES-128-GCM
    bool aesGcmEncrypt(const byte* key, const byte* nonce,
                       const byte* aad, u32 aadLen,
                       const byte* plaintext, u32 plaintextLen,
                       byte* ciphertext, byte* tag);
    bool aesGcmDecrypt(const byte* key, const byte* nonce,
                       const byte* aad, u32 aadLen,
                       const byte* ciphertext, u32 ciphertextLen,
                       const byte* tag, byte* plaintext);

    // Byte helpers
    static void putU16BE(byte* dst, u16 val);
    static void putU24BE(byte* dst, u32 val);
    static void putU64BE(byte* dst, u64 val);
    static u16 getU16BE(const byte* src);
    static u32 getU24BE(const byte* src);
};

#endif // WHIPNEXUS_TLSSERVERCONTEXT_H