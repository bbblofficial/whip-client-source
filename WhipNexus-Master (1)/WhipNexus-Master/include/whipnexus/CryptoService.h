#ifndef WHIPNEXUS_CRYPTOSERVICE_H
#define WHIPNEXUS_CRYPTOSERVICE_H

#include "Types.h"
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

// Service de cryptographie utilisant BCrypt (natif Windows)
class CryptoService {
private:
    BCRYPT_ALG_HANDLE hAesGcm;
    BCRYPT_ALG_HANDLE hEcdh;
    BCRYPT_ALG_HANDLE hEcdsa;
    BCRYPT_ALG_HANDLE hHmac;
    BCRYPT_ALG_HANDLE hRng;

    bool initialized;

public:
    CryptoService();
    ~CryptoService();

    bool init();
    void cleanup();

    // ECDH - Échange de clés éphémère
    bool generateEcdhKeyPair(byte* publicKeyOut, u32* publicKeyLengthOut, void** privateKeyHandle);
    bool deriveSessionKey(void* privateKeyHandle, const byte* peerPublicKey, u32 peerPublicKeyLength,
                          const byte* clientNonce, const byte* serverNonce, byte* sessionKeyOut);
    bool deriveRawSecret(void* privateKeyHandle, const byte* peerPublicKey, u32 peerPublicKeyLength,
                         byte* rawSecretOut);
    void freeKeyHandle(void* keyHandle);

    // HKDF-SHA256 for key derivation
    bool hkdfSha256(const byte* salt, u32 saltLength,
                    const byte* inputKeyMaterial, u32 ikmLength,
                    const byte* info, u32 infoLength,
                    byte* outputKeyMaterial, u32 okmLength);

    // AES-GCM - Chiffrement symétrique
    bool encrypt(const byte* plaintext, u32 plaintextLength,
                 const byte* key, u32 keyLength,
                 const byte* nonce, u32 nonceLength,
                 byte* ciphertextOut, u32* ciphertextLengthOut);

    bool decrypt(const byte* ciphertext, u32 ciphertextLength,
                 const byte* key, u32 keyLength,
                 const byte* nonce, u32 nonceLength,
                 byte* plaintextOut, u32* plaintextLengthOut);

    // HMAC-SHA256
    bool hmacSha256(const byte* data, u32 dataLength,
                    const byte* key, u32 keyLength,
                    byte* hmacOut);

    bool verifyHmac(const byte* data, u32 dataLength,
                    const byte* key, u32 keyLength,
                    const byte* expectedHmac);

    // Génération aléatoire cryptographique
    bool generateRandomBytes(byte* output, u32 length);
    bool generateNonce(byte* output);

    // ECDSA - Signature pour certificate pinning
    bool generateEcdsaKeyPair(byte* publicKeyOut, u32* publicKeyLengthOut, void** privateKeyHandle);
    bool signEcdsa(void* privateKeyHandle, const byte* data, u32 dataLength, byte* signatureOut, u32* signatureLengthOut);
    bool verifyEcdsa(const byte* publicKey, u32 publicKeyLength, const byte* data, u32 dataLength, const byte* signature, u32 signatureLength, bool preHashed = false);

    // ECDSA key persistence - export/import private key blob for file storage
    bool exportEcdsaPrivateKey(void* privateKeyHandle, byte* blobOut, u32 blobBufferSize, u32* blobLengthOut);
    bool importEcdsaKeyPair(const byte* blob, u32 blobLength, byte* publicKeyOut, u32* publicKeyLengthOut, void** privateKeyHandle);

    // SHA-256 hash
    bool sha256Hash(const byte* data, u32 dataLength, byte* hashOut);
};

#endif // WHIPNEXUS_CRYPTOSERVICE_H