#pragma optimize("", off)
#include "whipnexus/CryptoService.h"

#include <stdio.h>

#include "whipnexus/ProtocolConstants.h"
#include "whipnexus/SyscallManager.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

#pragma comment(lib, "bcrypt.lib")

// Extraire les coordonnées X,Y depuis une clé publique EC P-256 encodée en X.509
// SubjectPublicKeyInfo DER. Scan générique du BIT STRING contenant le point EC.
// Pas de dépendance sur crypt32 (compatible manual-map injection).
static bool extractEcPointFromX509(const byte* x509Key, u32 x509KeyLen, BYTE* pXout, BYTE* pYout) {
    VMProtectBeginMutation("extractEcPointFromX509");
    if (!x509Key || x509KeyLen < 26 + 65) return false;

    // Chercher le pattern BIT STRING contenant un point EC non compressé
    for (u32 i = 0; i + 67 <= x509KeyLen; i++) {
        if (x509Key[i] == 0x03) {
            u32 lenPos = i + 1;
            u32 contentStart = 0;
            u32 contentLen = 0;

            if (lenPos >= x509KeyLen) continue;
            byte lenByte = x509Key[lenPos];
            if (lenByte < 0x80) {
                contentLen = lenByte;
                contentStart = lenPos + 1;
            } else if (lenByte == 0x81 && lenPos + 1 < x509KeyLen) {
                contentLen = x509Key[lenPos + 1];
                contentStart = lenPos + 2;
            } else {
                continue;
            }

            if (contentLen == 66 && contentStart + 66 <= x509KeyLen) {
                if (x509Key[contentStart] == 0x00 && x509Key[contentStart + 1] == 0x04) {
                    SyscallManager::SecureMemCpy(pXout, x509Key + contentStart + 2, 32);
                    SyscallManager::SecureMemCpy(pYout, x509Key + contentStart + 2 + 32, 32);
                    return true;
                }
            }
        }
    }
    return false;
    VMProtectEnd();
}

// Construire manuellement le X.509 SubjectPublicKeyInfo DER pour une clé EC P-256.
// Structure fixe de 91 bytes, pas de dépendance sur crypt32 (compatible manual-map injection).
static bool buildX509FromEcPoint(const byte* pX, const byte* pY, byte* x509Out, u32* x509LenOut) {
    VMProtectBeginMutation("buildX509FromEcPoint");
    // Header fixe pour P-256 SubjectPublicKeyInfo (27 bytes: header + 0x04 uncompressed marker)
    static const byte x509Header[27] = {
        0x30, 0x59,                                                     // SEQUENCE (89 bytes)
          0x30, 0x13,                                                   //   SEQUENCE (19 bytes) - AlgorithmIdentifier
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,     //     OID ecPublicKey (1.2.840.10045.2.1)
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID prime256v1 (1.2.840.10045.3.1.7)
          0x03, 0x42, 0x00,                                             //   BIT STRING (66 bytes, 0 unused bits)
            0x04                                                        //     Uncompressed point marker
    };

    SyscallManager::SecureMemCpy(x509Out, x509Header, 27);
    SyscallManager::SecureMemCpy(x509Out + 27, pX, 32);     // X coordinate
    SyscallManager::SecureMemCpy(x509Out + 59, pY, 32);     // Y coordinate
    *x509LenOut = 91;
    return true;
    VMProtectEnd();
}

CryptoService::CryptoService()
    : hAesGcm(nullptr), hEcdh(nullptr), hEcdsa(nullptr), hHmac(nullptr), hRng(nullptr), initialized(false) {
    VMProtectBeginMutation("CryptoService_ctor");
    VMProtectEnd();
}

CryptoService::~CryptoService() {
    VMProtectBeginMutation("CryptoService_dtor");
    cleanup();
    VMProtectEnd();
}

bool CryptoService::init() {
    VMProtectBeginMutation("CryptoService_init");
    if (initialized) return true;

    NTSTATUS status;

    // Ouvrir l'algorithme AES-GCM
    status = BCryptOpenAlgorithmProvider(&hAesGcm, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptSetProperty(hAesGcm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        cleanup();
        return false;
    }

    // Ouvrir l'algorithme ECDH (secp256r1 / NIST P-256)
    status = BCryptOpenAlgorithmProvider(&hEcdh, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        cleanup();
        return false;
    }

    // Ouvrir l'algorithme ECDSA P-256 (distinct de ECDH pour la signature)
    status = BCryptOpenAlgorithmProvider(&hEcdsa, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        cleanup();
        return false;
    }

    // Ouvrir l'algorithme HMAC-SHA256
    status = BCryptOpenAlgorithmProvider(&hHmac, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        cleanup();
        return false;
    }

    // Ouvrir le générateur aléatoire
    status = BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        cleanup();
        return false;
    }

    initialized = true;
    return true;
    VMProtectEnd();
}

void CryptoService::cleanup() {
    VMProtectBeginMutation("CryptoService_cleanup");
    if (hAesGcm) {
        BCryptCloseAlgorithmProvider(hAesGcm, 0);
        hAesGcm = nullptr;
    }
    if (hEcdh) {
        BCryptCloseAlgorithmProvider(hEcdh, 0);
        hEcdh = nullptr;
    }
    if (hEcdsa) {
        BCryptCloseAlgorithmProvider(hEcdsa, 0);
        hEcdsa = nullptr;
    }
    if (hHmac) {
        BCryptCloseAlgorithmProvider(hHmac, 0);
        hHmac = nullptr;
    }
    if (hRng) {
        BCryptCloseAlgorithmProvider(hRng, 0);
        hRng = nullptr;
    }
    initialized = false;
    VMProtectEnd();
}

bool CryptoService::generateEcdhKeyPair(byte* publicKeyOut, u32* publicKeyLengthOut, void** privateKeyHandle) {
    VMProtectBeginMutation("CryptoService_generateEcdhKeyPair");
    if (!initialized) return false;

    // Générer la paire de clés ECDH avec CNG
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = BCryptGenerateKeyPair(hEcdh, &hKey, 256, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptFinalizeKeyPair(hKey, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        return false;
    }

    // Exporter la clé publique au format BCRYPT_ECCPUBLIC_BLOB
    byte blobBuffer[256];
    ULONG blobSize = 0;
    status = BCryptExportKey(hKey, nullptr, BCRYPT_ECCPUBLIC_BLOB, blobBuffer, sizeof(blobBuffer), &blobSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        return false;
    }

    // Structure BCRYPT_ECCKEY_BLOB pour P-256:
    // ULONG Magic (4 bytes) = BCRYPT_ECDH_PUBLIC_P256_MAGIC
    // ULONG cbKey (4 bytes) = 32
    // byte X[32]
    // byte Y[32]

    if (blobSize < 72) {
        BCryptDestroyKey(hKey);
        return false;
    }

    ULONG cbKey = *(ULONG*)(blobBuffer + 4);
    if (cbKey != 32) {
        BCryptDestroyKey(hKey);
        return false;
    }

    byte* pX = blobBuffer + 8;
    byte* pY = blobBuffer + 40; // 8 + 32

    // Construire le X.509 SubjectPublicKeyInfo manuellement (pas de crypt32 nécessaire).
    // Compatible manual-map injection où CryptEncodeObjectEx pourrait ne pas être résolu.
    byte x509Buffer[91];
    u32 x509Size = 0;
    if (!buildX509FromEcPoint(pX, pY, x509Buffer, &x509Size)) {
        BCryptDestroyKey(hKey);
        return false;
    }

    // Copie sécurisée de la clé publique encodée X.509
    SyscallManager::SecureMemCpy(publicKeyOut, x509Buffer, x509Size);
    *publicKeyLengthOut = x509Size;

    *privateKeyHandle = (void*)hKey;
    return true;
    VMProtectEnd();
}

bool CryptoService::deriveSessionKey(void* privateKeyHandle, const byte* peerPublicKey, u32 peerPublicKeyLength,
                                      const byte* clientNonce, const byte* serverNonce, byte* sessionKeyOut) {
    VMProtectBeginMutation("CryptoService_deriveSessionKey");

    if (!initialized || !privateKeyHandle || !clientNonce || !serverNonce) {
        return false;
    }

    // SECURITY: Derive raw ECDH shared secret first
    byte rawSecret[32];
    if (!deriveRawSecret(privateKeyHandle, peerPublicKey, peerPublicKeyLength, rawSecret)) {
        return false;
    }

    // SECURITY: Use HKDF with nonce binding to prevent replay attacks
    // Salt = clientNonce || serverNonce (64 bytes)
    byte salt[64];
    SyscallManager::SecureMemCpy(salt, clientNonce, 32);
    SyscallManager::SecureMemCpy(salt + 32, serverNonce, 32);

    // Info = "whip-session-key-v1"
    const char* info = "whip-session-key-v1";
    u32 infoLen = (u32)strlen(info);

    // Apply HKDF to derive session key
    bool result = hkdfSha256(salt, 64, rawSecret, 32, (const byte*)info, infoLen, sessionKeyOut, 32);

    // Clear sensitive data
    SecureZeroMemory(rawSecret, sizeof(rawSecret));
    SecureZeroMemory(salt, sizeof(salt));

    return result;
    VMProtectEnd();
}

bool CryptoService::deriveRawSecret(void* privateKeyHandle, const byte* peerPublicKey, u32 peerPublicKeyLength,
                                     byte* rawSecretOut) {
    VMProtectBeginMutation("CryptoService_deriveRawSecret");
    if (!initialized || !privateKeyHandle) return false;

    BCRYPT_KEY_HANDLE hPrivateKey = (BCRYPT_KEY_HANDLE)privateKeyHandle;

    BYTE ecX[32];
    BYTE ecY[32];
    if (!extractEcPointFromX509(peerPublicKey, peerPublicKeyLength, ecX, ecY)) return false;

    BYTE bcryptBlob[72];
    ULONG* pMagic = (ULONG*)bcryptBlob;
    ULONG* pCbKey = (ULONG*)(bcryptBlob + 4);
    *pMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    *pCbKey = 32;
    SyscallManager::SecureMemCpy(bcryptBlob + 8, ecX, 32);
    SyscallManager::SecureMemCpy(bcryptBlob + 40, ecY, 32);

    BCRYPT_KEY_HANDLE hPeerKey = nullptr;
    NTSTATUS status = BCryptImportKeyPair(hEcdh, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                                           &hPeerKey, bcryptBlob, sizeof(bcryptBlob), 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    BCRYPT_SECRET_HANDLE hSecret = nullptr;
    status = BCryptSecretAgreement(hPrivateKey, hPeerKey, &hSecret, 0);
    BCryptDestroyKey(hPeerKey);
    if (!BCRYPT_SUCCESS(status)) return false;

    // Obtenir le secret brut (x-coordinate) — pour TLS pre-master secret
    DWORD rawLen = 0;
    status = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, nullptr,
                             nullptr, 0, &rawLen, 0);
    if (!BCRYPT_SUCCESS(status) || rawLen == 0) {
        BCryptDestroySecret(hSecret);
        return false;
    }

    byte rawSecret[64];
    if (rawLen > sizeof(rawSecret)) {
        BCryptDestroySecret(hSecret);
        return false;
    }

    status = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, nullptr,
                             rawSecret, rawLen, &rawLen, 0);
    BCryptDestroySecret(hSecret);
    if (!BCRYPT_SUCCESS(status)) return false;

    // Inverser little-endian -> big-endian
    for (DWORD i = 0; i < rawLen / 2; i++) {
        byte tmp = rawSecret[i];
        rawSecret[i] = rawSecret[rawLen - 1 - i];
        rawSecret[rawLen - 1 - i] = tmp;
    }

    SyscallManager::SecureMemCpy(rawSecretOut, rawSecret, rawLen > 32 ? 32 : rawLen);
    SyscallManager::SecureZero(rawSecret, sizeof(rawSecret));
    return true;
    VMProtectEnd();
}

void CryptoService::freeKeyHandle(void* keyHandle) {
    VMProtectBeginMutation("CryptoService_freeKeyHandle");
    if (keyHandle) {
        BCryptDestroyKey((BCRYPT_KEY_HANDLE)keyHandle);
    }
    VMProtectEnd();
}

bool CryptoService::encrypt(const byte* plaintext, u32 plaintextLength,
                             const byte* key, u32 keyLength,
                             const byte* nonce, u32 nonceLength,
                             byte* ciphertextOut, u32* ciphertextLengthOut) {
    VMProtectBeginMutation("CryptoService_encrypt");

    if (!initialized) return false;

    // Générer une clé AES-GCM
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = BCryptGenerateSymmetricKey(hAesGcm, &hKey, nullptr, 0,
                                                  (PUCHAR)key, keyLength, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    // Préparer les paramètres GCM
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = nonceLength;
    authInfo.pbTag = ciphertextOut + plaintextLength; // Tag à la fin
    authInfo.cbTag = 16; // GCM tag = 16 bytes

    DWORD cbResult = 0;
    status = BCryptEncrypt(hKey, (PUCHAR)plaintext, plaintextLength,
                           &authInfo, nullptr, 0,
                           ciphertextOut, plaintextLength, &cbResult, 0);

    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status)) return false;

    *ciphertextLengthOut = cbResult + 16; // ciphertext + tag
    return true;
    VMProtectEnd();
}

bool CryptoService::decrypt(const byte* ciphertext, u32 ciphertextLength,
                             const byte* key, u32 keyLength,
                             const byte* nonce, u32 nonceLength,
                             byte* plaintextOut, u32* plaintextLengthOut) {
    VMProtectBeginMutation("CryptoService_decrypt");

    // Validate ciphertext length (min 16 bytes for tag)
    // Upper bound is validated by PacketCodec using MAX_PAYLOAD_SIZE
    if (!initialized || ciphertextLength < 16) {
        return false;
    }

    // Générer une clé AES-GCM
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = BCryptGenerateSymmetricKey(hAesGcm, &hKey, nullptr, 0,
                                                  (PUCHAR)key, keyLength, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    // Le tag est à la fin du ciphertext
    u32 actualCiphertextLength = ciphertextLength - 16;
    const byte* tag = ciphertext + actualCiphertextLength;

    // Préparer les paramètres GCM
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = nonceLength;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = 16;

    DWORD cbResult = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, actualCiphertextLength,
                           &authInfo, nullptr, 0,
                           plaintextOut, actualCiphertextLength, &cbResult, 0);

    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status)) return false;

    *plaintextLengthOut = cbResult;
    return true;
    VMProtectEnd();
}

bool CryptoService::hmacSha256(const byte* data, u32 dataLength,
                                const byte* key, u32 keyLength,
                                byte* hmacOut) {
    VMProtectBeginMutation("CryptoService_hmacSha256");

    if (!initialized) return false;

    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status = BCryptCreateHash(hHmac, &hHash, nullptr, 0,
                                        (PUCHAR)key, keyLength, BCRYPT_HASH_REUSABLE_FLAG);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptHashData(hHash, (PUCHAR)data, dataLength, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        return false;
    }

    DWORD hashLength = 32; // SHA-256 = 32 bytes
    status = BCryptFinishHash(hHash, hmacOut, hashLength, 0);
    BCryptDestroyHash(hHash);

    return BCRYPT_SUCCESS(status);
    VMProtectEnd();
}

bool CryptoService::verifyHmac(const byte* data, u32 dataLength,
                                const byte* key, u32 keyLength,
                                const byte* expectedHmac) {
    VMProtectBeginMutation("CryptoService_verifyHmac");
    byte computed[32];
    if (!hmacSha256(data, dataLength, key, keyLength, computed)) {
        return false;
    }

    // Comparaison constant-time
    int result = 0;
    for (int i = 0; i < 32; i++) {
        result |= computed[i] ^ expectedHmac[i];
    }
    return result == 0;
    VMProtectEnd();
}

bool CryptoService::generateRandomBytes(byte* output, u32 length) {
    VMProtectBeginMutation("CryptoService_generateRandomBytes");
    if (!initialized) return false;

    NTSTATUS status = BCryptGenRandom(hRng, output, length, 0);
    return BCRYPT_SUCCESS(status);
    VMProtectEnd();
}

bool CryptoService::generateNonce(byte* output) {
    return generateRandomBytes(output, ProtocolConstants::NONCE_SIZE);
}

bool CryptoService::generateEcdsaKeyPair(byte* publicKeyOut, u32* publicKeyLengthOut, void** privateKeyHandle) {
    VMProtectBeginMutation("CryptoService_generateEcdsaKeyPair");
    if (!initialized) return false;

    // Générer une paire de clés ECDSA P-256 avec le provider ECDSA dédié
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = BCryptGenerateKeyPair(hEcdsa, &hKey, 256, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptFinalizeKeyPair(hKey, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        return false;
    }

    // Exporter la clé publique au format X.509 (même logique que generateEcdhKeyPair)
    byte blobBuffer[256];
    ULONG blobSize = 0;
    status = BCryptExportKey(hKey, nullptr, BCRYPT_ECCPUBLIC_BLOB, blobBuffer, sizeof(blobBuffer), &blobSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        return false;
    }

    if (blobSize < 72) {
        BCryptDestroyKey(hKey);
        return false;
    }

    ULONG cbKey = *(ULONG*)(blobBuffer + 4);
    if (cbKey != 32) {
        BCryptDestroyKey(hKey);
        return false;
    }

    byte* pX = blobBuffer + 8;
    byte* pY = blobBuffer + 40;

    // Construire le X.509 SubjectPublicKeyInfo manuellement (pas de crypt32 nécessaire)
    byte x509Buffer[91];
    u32 x509Size = 0;
    if (!buildX509FromEcPoint(pX, pY, x509Buffer, &x509Size)) {
        BCryptDestroyKey(hKey);
        return false;
    }

    SyscallManager::SecureMemCpy(publicKeyOut, x509Buffer, x509Size);
    *publicKeyLengthOut = x509Size;

    *privateKeyHandle = (void*)hKey;
    return true;
    VMProtectEnd();
}

bool CryptoService::exportEcdsaPrivateKey(void* privateKeyHandle, byte* blobOut, u32 blobBufferSize, u32* blobLengthOut) {
    VMProtectBeginMutation("CryptoService_exportEcdsaPrivateKey");
    if (!initialized || !privateKeyHandle) return false;

    BCRYPT_KEY_HANDLE hKey = (BCRYPT_KEY_HANDLE)privateKeyHandle;

    // Export au format ECCPRIVATE_BLOB: Magic(4) + cbKey(4) + X(32) + Y(32) + d(32) = 104 bytes pour P-256
    ULONG blobSize = 0;
    NTSTATUS status = BCryptExportKey(hKey, nullptr, BCRYPT_ECCPRIVATE_BLOB, blobOut, blobBufferSize, &blobSize, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    *blobLengthOut = blobSize;
    return true;
    VMProtectEnd();
}

bool CryptoService::importEcdsaKeyPair(const byte* blob, u32 blobLength, byte* publicKeyOut, u32* publicKeyLengthOut, void** privateKeyHandle) {
    VMProtectBeginMutation("CryptoService_importEcdsaKeyPair");
    if (!initialized || !blob || blobLength < 104) return false;

    // Vérifier le magic ECDSA_PRIVATE_P256
    ULONG magic = *(const ULONG*)blob;
    if (magic != BCRYPT_ECDSA_PRIVATE_P256_MAGIC) return false;

    ULONG cbKey = *(const ULONG*)(blob + 4);
    if (cbKey != 32) return false;

    // Importer la clé privée ECDSA
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = BCryptImportKeyPair(hEcdsa, nullptr, BCRYPT_ECCPRIVATE_BLOB,
                                          &hKey, (PUCHAR)blob, blobLength, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    // Extraire X, Y depuis le blob pour construire la clé publique X.509
    const byte* pX = blob + 8;
    const byte* pY = blob + 40;

    byte x509Buffer[91];
    u32 x509Size = 0;
    if (!buildX509FromEcPoint(pX, pY, x509Buffer, &x509Size)) {
        BCryptDestroyKey(hKey);
        return false;
    }

    SyscallManager::SecureMemCpy(publicKeyOut, x509Buffer, x509Size);
    *publicKeyLengthOut = x509Size;
    *privateKeyHandle = (void*)hKey;
    return true;
    VMProtectEnd();
}

bool CryptoService::signEcdsa(void* privateKeyHandle, const byte* data, u32 dataLength, byte* signatureOut, u32* signatureLengthOut) {
    VMProtectBeginMutation("CryptoService_signEcdsa");

    if (!initialized || !privateKeyHandle) return false;

    BCRYPT_KEY_HANDLE hKey = (BCRYPT_KEY_HANDLE)privateKeyHandle;

    // Hash des données avec SHA-256
    byte hash[32];
    if (!sha256Hash(data, dataLength, hash)) {
        return false;
    }

    // Signer le hash avec ECDSA
    DWORD sigLength = 0;
    NTSTATUS status = BCryptSignHash(hKey, nullptr, hash, 32, nullptr, 0, &sigLength, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    if (sigLength > 256) return false; // Signature trop grande

    byte sigBuffer[256];
    status = BCryptSignHash(hKey, nullptr, hash, 32, sigBuffer, sigLength, &sigLength, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    SyscallManager::SecureMemCpy(signatureOut, sigBuffer, sigLength);
    *signatureLengthOut = sigLength;
    return true;
    VMProtectEnd();
}

bool CryptoService::verifyEcdsa(const byte* publicKey, u32 publicKeyLength, const byte* data, u32 dataLength, const byte* signature, u32 signatureLength, bool preHashed) {
    VMProtectBeginMutation("CryptoService_verifyEcdsa");
    if (!initialized) return false;

    // Convertir la signature DER en format RAW (r||s, 64 bytes) si nécessaire
    // BCrypt attend le format RAW pour ECDSA P-256
    byte rawSig[64];
    const byte* sigToVerify = signature;
    u32 sigToVerifyLen = signatureLength;

    if (signatureLength == 64) {
        // Déjà en format RAW (r||s)
        sigToVerify = signature;
        sigToVerifyLen = 64;
    } else if (signatureLength >= 8 && signature[0] == 0x30) {
        // Format DER: 30 <total_len> 02 <len_r> <r> 02 <len_s> <s>
        u32 pos = 2; // Skip SEQUENCE tag + length

        // Parse r
        if (pos >= signatureLength || signature[pos] != 0x02) return false;
        pos++;
        u32 rLenOrig = signature[pos];
        pos++;
        const byte* rData = signature + pos;
        u32 rLen = rLenOrig;
        // Ignorer le padding 0x00 (unsigned integer encoding DER)
        if (rLen > 0 && rData[0] == 0x00) {
            rData++;
            rLen--;
        }
        if (rLen > 32) return false;
        // Pad gauche avec des zéros si r < 32 bytes
        SyscallManager::SecureMemSet(rawSig, 0, 32);
        SyscallManager::SecureMemCpy(rawSig + (32 - rLen), rData, rLen);
        pos += rLenOrig; // Avancer de la longueur originale

        // Parse s
        if (pos >= signatureLength || signature[pos] != 0x02) return false;
        pos++;
        u32 sLenOrig = signature[pos];
        pos++;
        const byte* sData = signature + pos;
        u32 sLen = sLenOrig;
        if (sLen > 0 && sData[0] == 0x00) {
            sData++;
            sLen--;
        }
        if (sLen > 32) return false;
        SyscallManager::SecureMemSet(rawSig + 32, 0, 32);
        SyscallManager::SecureMemCpy(rawSig + 32 + (32 - sLen), sData, sLen);

        sigToVerify = rawSig;
        sigToVerifyLen = 64;
    } else {
        return false;
    }

    // Extraire les coordonnées EC depuis le X.509 SubjectPublicKeyInfo (BCrypt only, pas de crypt32)
    BYTE ecX[32];
    BYTE ecY[32];
    if (!extractEcPointFromX509(publicKey, publicKeyLength, ecX, ecY)) {
        return false;
    }

    // Construire BCRYPT_ECCPUBLIC_BLOB
    BYTE bcryptBlob[72];
    ULONG* pMagic = (ULONG*)bcryptBlob;
    ULONG* pCbKey = (ULONG*)(bcryptBlob + 4);

    *pMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    *pCbKey = 32;

    SyscallManager::SecureMemCpy(bcryptBlob + 8, ecX, 32);
    SyscallManager::SecureMemCpy(bcryptBlob + 40, ecY, 32);

    // Importer la clé publique avec le provider ECDSA persistant
    BCRYPT_KEY_HANDLE hPubKey = nullptr;
    NTSTATUS status = BCryptImportKeyPair(hEcdsa, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                                  &hPubKey, bcryptBlob, sizeof(bcryptBlob), 0);
    if (!BCRYPT_SUCCESS(status)) {
        return false;
    }

    // Hash des données (sauf si déjà pré-hashées)
    byte hashBuf[32];
    const byte* hashToVerify;
    if (preHashed) {
        hashToVerify = data;
    } else {
        if (!sha256Hash(data, dataLength, hashBuf)) {
            BCryptDestroyKey(hPubKey);
            return false;
        }
        hashToVerify = hashBuf;
    }

    // Vérifier la signature (format brut: r||s, 64 bytes)+
    status = BCryptVerifySignature(hPubKey, nullptr, (PUCHAR)hashToVerify, 32,
                                    (PUCHAR)sigToVerify, 64, 0);

    BCryptDestroyKey(hPubKey);

    return BCRYPT_SUCCESS(status);
    VMProtectEnd();
}

bool CryptoService::sha256Hash(const byte* data, u32 dataLength, byte* hashOut) {
    VMProtectBeginMutation("CryptoService_sha256Hash");
    if (!initialized) return false;

    // Ouvrir un provider SHA-256 (non-HMAC)
    BCRYPT_ALG_HANDLE hSha = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hSha, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hSha, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hSha, 0);
        return false;
    }

    status = BCryptHashData(hHash, (PUCHAR)data, dataLength, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hSha, 0);
        return false;
    }

    DWORD hashLength = 32;
    status = BCryptFinishHash(hHash, hashOut, hashLength, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hSha, 0);

    return BCRYPT_SUCCESS(status);
    VMProtectEnd();
}

bool CryptoService::hkdfSha256(const byte* salt, u32 saltLength,
                                const byte* inputKeyMaterial, u32 ikmLength,
                                const byte* info, u32 infoLength,
                                byte* outputKeyMaterial, u32 okmLength) {
    VMProtectBeginMutation("CryptoService_hkdfSha256");
    if (!initialized || !inputKeyMaterial || !outputKeyMaterial || okmLength == 0) {
        return false;
    }

    // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
    byte prk[32];
    if (salt && saltLength > 0) {
        if (!hmacSha256(inputKeyMaterial, ikmLength, salt, saltLength, prk)) {
            return false;
        }
    } else {
        // If no salt, use zeros
        byte zeroSalt[32] = {0};
        if (!hmacSha256(inputKeyMaterial, ikmLength, zeroSalt, 32, prk)) {
            return false;
        }
    }

    // HKDF-Expand (RFC 5869): T(i) = HMAC-SHA256(PRK, T(i-1) || info || counter)
    // Max output: 255 * 32 = 8160 bytes
    u32 numBlocks = (okmLength + 31) / 32;
    if (numBlocks > 255 || infoLength > 224) {
        SecureZeroMemory(prk, sizeof(prk));
        return false;
    }

    byte prevBlock[32];
    byte expandInput[32 + 224 + 1]; // T(i-1) + info + counter
    u32 bytesWritten = 0;

    for (u32 i = 1; i <= numBlocks; i++) {
        u32 expandInputLen = 0;

        // T(i-1) pour i > 1
        if (i > 1) {
            SyscallManager::SecureMemCpy(expandInput, prevBlock, 32);
            expandInputLen = 32;
        }

        // info
        if (info && infoLength > 0) {
            SyscallManager::SecureMemCpy(expandInput + expandInputLen, info, infoLength);
            expandInputLen += infoLength;
        }

        // counter byte
        expandInput[expandInputLen] = (byte)i;
        expandInputLen++;

        if (!hmacSha256(expandInput, expandInputLen, prk, 32, prevBlock)) {
            SecureZeroMemory(prk, sizeof(prk));
            SecureZeroMemory(prevBlock, sizeof(prevBlock));
            SecureZeroMemory(expandInput, sizeof(expandInput));
            return false;
        }

        // Copier dans le buffer de sortie
        u32 toCopy = okmLength - bytesWritten;
        if (toCopy > 32) toCopy = 32;
        SyscallManager::SecureMemCpy(outputKeyMaterial + bytesWritten, prevBlock, toCopy);
        bytesWritten += toCopy;
    }

    // Clear sensitive data
    SecureZeroMemory(prk, sizeof(prk));
    SecureZeroMemory(prevBlock, sizeof(prevBlock));
    SecureZeroMemory(expandInput, sizeof(expandInput));

    return true;
    VMProtectEnd();
}

