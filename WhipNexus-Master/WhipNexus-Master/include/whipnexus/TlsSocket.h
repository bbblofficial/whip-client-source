#ifndef WHIPNEXUS_TLSSOCKET_H
#define WHIPNEXUS_TLSSOCKET_H

#include "Types.h"
#include "TcpSocket.h"
#include "CryptoService.h"

// TLS 1.3 / 1.2 client implementation using BCrypt (no SChannel/SSPI).
// Supports cipher suites: TLS_AES_256_GCM_SHA384                     (0x1302) [TLS 1.3]
//                         TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    (0xC02C) [TLS 1.2]
//                         TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384      (0xC030) [TLS 1.2]
// Certificate validation: CertificateVerify (TLS 1.3) + self-signed validation.
class TlsSocket {
private:
    TcpSocket rawSocket;
    CryptoService* crypto;

    // BCrypt handles for TLS-specific operations
    BCRYPT_ALG_HANDLE hAesGcm;
    BCRYPT_ALG_HANDLE hSha256;
    BCRYPT_ALG_HANDLE hSha384;
    BCRYPT_ALG_HANDLE hHmacSha256;
    BCRYPT_ALG_HANDLE hHmacSha384;

    // TLS handshake state
    byte clientRandom[32];
    byte serverRandom[32];
    byte masterSecret[48];

    // Traffic keys (AES-256-GCM)
    byte clientWriteKey[32];
    byte serverWriteKey[32];
    byte clientWriteIV[4];   // implicit nonce prefix (TLS 1.2)
    byte serverWriteIV[4];

    // TLS 1.3 IVs (12 bytes, XOR with seq num)
    byte clientWriteIV13[12];
    byte serverWriteIV13[12];

    // TLS 1.3 handshake keys/IVs
    byte hsClientWriteKey[32];
    byte hsServerWriteKey[32];
    byte hsClientWriteIV[12];
    byte hsServerWriteIV[12];

    // TLS 1.3 traffic secrets (for key derivation)
    byte clientHsTrafficSecret[48];
    byte serverHsTrafficSecret[48];
    byte handshakeSecret[48];

    // TLS 1.3 handshake sequence numbers
    u64 hsClientSeqNum;
    u64 hsServerSeqNum;

    // Sequence numbers for GCM nonce construction
    u64 clientSeqNum;
    u64 serverSeqNum;

    // TLS 1.3 state
    bool isTls13;
    bool handshakeKeysActive;
    void* clientEcdhPrivKey;

    // Server certificate DER (for validation)
    byte serverCertDer[4096];
    u32 serverCertDerLen;

    // Handshake transcript (accumulated for Finished verification)
    byte* handshakeHash;         // running SHA-384 hash state
    BCRYPT_HASH_HANDLE hHandshakeHash;

    // Server certificate public key (raw SubjectPublicKeyInfo)
    byte serverCertPubKey[256];
    u32 serverCertPubKeyLen;

    // Chosen cipher suite
    u16 negotiatedCipher;

    // State
    bool tlsEstablished;
    bool cipherActive;           // true after ChangeCipherSpec sent
    bool plainMode;              // true = bypass TLS, use raw TCP (for localhost IPC)

    // Receive buffer for decrypted application data
    static const u32 RECV_BUF_SIZE = 32768;
    byte recvBuf[RECV_BUF_SIZE];
    u32 recvBufStart;
    u32 recvBufLen;

    // Raw receive buffer for TLS records
    static const u32 RAW_BUF_SIZE = 18432; // 5 header + 16384 payload + 256 overhead + tag
    byte rawRecvBuf[RAW_BUF_SIZE];

    // Record buffer for TLS 1.3 decryption (per-instance to avoid race conditions)
    // TLS max record size is 16KB, we use 32KB for safety margin
    static const u32 RECORD_BUF_SIZE = 32 * 1024; // 32 KB
    byte recordBuf[RECORD_BUF_SIZE];

    // Multithreading for parallel decrypt - simple on-demand threads
    struct DecryptTask {
        TlsSocket* socket;
        byte key[32];
        byte nonce[12];
        byte aad[13];
        u32 aadLen;
        const byte* ciphertext;
        u32 ciphertextLen;
        const byte* tag;
        byte* plaintext;
        volatile bool complete;
        bool success;
    };

    static void* decryptTaskEntry(void* param);

    // TLS constants
    static const byte TLS_CONTENT_CHANGE_CIPHER  = 20;
    static const byte TLS_CONTENT_ALERT          = 21;
    static const byte TLS_CONTENT_HANDSHAKE      = 22;
    static const byte TLS_CONTENT_APPLICATION    = 23;

    static const byte TLS_HS_CLIENT_HELLO        = 1;
    static const byte TLS_HS_SERVER_HELLO        = 2;
    static const byte TLS_HS_ENCRYPTED_EXTENSIONS = 8;
    static const byte TLS_HS_CERTIFICATE         = 11;
    static const byte TLS_HS_SERVER_KEY_EXCHANGE  = 12;
    static const byte TLS_HS_SERVER_HELLO_DONE   = 14;
    static const byte TLS_HS_CERTIFICATE_VERIFY  = 15;
    static const byte TLS_HS_CLIENT_KEY_EXCHANGE  = 16;
    static const byte TLS_HS_FINISHED            = 20;

    static const u16  TLS_VERSION_12             = 0x0303;
    static const u16  TLS_VERSION_13             = 0x0304;
    static const u16  TLS_CIPHER_AES_256_GCM_SHA384 = 0x1302;
    static const u16  TLS_CIPHER_ECDHE_ECDSA_AES256_GCM_SHA384 = 0xC02C;
    static const u16  TLS_CIPHER_ECDHE_RSA_AES256_GCM_SHA384  = 0xC030;

    static const u16  TLS_EXT_SUPPORTED_VERSIONS = 0x002B;
    static const u16  TLS_EXT_KEY_SHARE          = 0x0033;

public:
    TlsSocket();
    ~TlsSocket();

    void init(SyscallResolver* res, CryptoService* cryptoService);

    // Enable plain (non-TLS) mode for localhost IPC — must be called before connect()
    void setPlainMode(bool enabled) { plainMode = enabled; }

    // Same API as TcpSocket
    bool connect(const char* host, u16 port);
    void disconnect();
    bool send(const byte* data, u32 length);
    i32 receive(byte* buffer, u32 bufferSize);
    bool receiveExact(byte* buffer, u32 length);
    bool isConnected() const;
    bool setTimeout(u32 timeoutMs);

    // Cancel pending I/O to unblock a blocking receive from another thread.
    void cancelPendingIo() { rawSocket.cancelIo(); }

private:
    // BCrypt init/cleanup for TLS-specific algorithms
    bool initAlgorithms();
    void cleanupAlgorithms();

    // TLS Record Layer
    bool sendRecord(byte contentType, const byte* data, u32 len);
    bool recvRecord(byte& contentType, byte* data, u32& len, u32 maxLen);

    // TLS Handshake (common)
    bool performTlsHandshake();
    bool sendClientHello();
    bool processServerMessages(byte* serverEcdhPub, u32& serverEcdhPubLen);

    // TLS 1.2 Handshake
    bool sendClientKeyExchange(const byte* serverEcdhPub, u32 pubLen);
    bool sendChangeCipherSpec();
    bool sendFinished();
    bool recvServerChangeCipherSpecAndFinished();

    // TLS 1.3 Handshake
    bool processEncryptedHandshakeMessages();
    bool sendClientFinished13();
    bool computeFinishedVerify13(const byte* baseKey, byte* verifyDataOut);

    // TLS 1.3 Key Schedule
    bool hkdfExtract384(const byte* salt, u32 saltLen,
                        const byte* ikm, u32 ikmLen,
                        byte* prkOut);
    bool hkdfExpandLabel384(const byte* secret,
                            const char* label, u32 labelLen,
                            const byte* context, u32 contextLen,
                            byte* output, u32 outputLen);
    bool deriveHandshakeKeys(const byte* sharedSecret, u32 sharedSecretLen);
    bool deriveApplicationKeys();
    bool deriveTrafficKeys13(const byte* trafficSecret,
                             byte* keyOut, byte* ivOut);

    // TLS 1.3 Certificate Validation
    bool verifyCertificateVerify13(const byte* signature, u32 sigLen, u16 sigAlgorithm);
    bool validateSelfSignedCert(const byte* certDer, u32 certDerLen);

    // Handshake transcript
    bool initHandshakeHash();
    bool updateHandshakeHash(const byte* data, u32 len);
    bool finalizeHandshakeHash(byte* hashOut);
    bool getHandshakeHash(byte* hashOut);  // snapshot without finalizing

    // TLS PRF (P_SHA384 for AES_256_GCM_SHA384 cipher suites)
    bool prf(const byte* secret, u32 secretLen,
             const char* label,
             const byte* seed, u32 seedLen,
             byte* output, u32 outputLen);

    bool hmacSha384(const byte* key, u32 keyLen,
                    const byte* data, u32 dataLen,
                    byte* out);

    // AES-256-GCM with AAD (TLS record encryption)
    bool aesGcmEncrypt(const byte* key, const byte* nonce,
                       const byte* aad, u32 aadLen,
                       const byte* plaintext, u32 plaintextLen,
                       byte* ciphertext, byte* tag);

    bool aesGcmDecrypt(const byte* key, const byte* nonce,
                       const byte* aad, u32 aadLen,
                       const byte* ciphertext, u32 ciphertextLen,
                       const byte* tag,
                       byte* plaintext);

    // Key derivation (TLS 1.2)
    bool deriveKeys();

    // ServerKeyExchange signature verification (TLS 1.2)
    bool verifyServerKeyExchangeSignature(const byte* hsBody, u32 hsLen,
                                           byte pubKeyLen);

    // Helpers
    static void putU16BE(byte* dst, u16 val);
    static void putU24BE(byte* dst, u32 val);
    static void putU64BE(byte* dst, u64 val);
    static u16 getU16BE(const byte* src);
    static u32 getU24BE(const byte* src);
};

#endif // WHIPNEXUS_TLSSOCKET_H
