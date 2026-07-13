#include "crypto.h"
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

// Macro NT_SUCCESS pour vérifier les statuts NTSTATUS de BCrypt
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

struct whip_crypto_ctx
{
    BCRYPT_ALG_HANDLE  chacha_alg;
    BCRYPT_KEY_HANDLE  session_key;
    unsigned char      session_key_bytes[WHIP_SESSION_KEY_SIZE];
    unsigned long long nonce_counter;
};

static BCRYPT_ALG_HANDLE g_rng_alg = NULL;

// ─── Initialisation ──────────────────────────────────────────────────────────

whip_crypto_ctx* whip_crypto_init(void)
{
    if (!g_rng_alg) {
        BCryptOpenAlgorithmProvider(&g_rng_alg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    }
    return NULL;
}

void whip_crypto_destroy(whip_crypto_ctx* ctx)
{
    if (!ctx) return;

    if (ctx->session_key)
        BCryptDestroyKey(ctx->session_key);
    if (ctx->chacha_alg)
        BCryptCloseAlgorithmProvider(ctx->chacha_alg, 0);

    SecureZeroMemory(ctx, sizeof(*ctx));
    HeapFree(GetProcessHeap(), 0, ctx);
}

// ─── Génération aléatoire ────────────────────────────────────────────────────

int whip_random_bytes(unsigned char* buf, unsigned int len)
{
    if (!g_rng_alg) {
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&g_rng_alg, BCRYPT_RNG_ALGORITHM, NULL, 0)))
            return 0;
    }

    return NT_SUCCESS(BCryptGenRandom(g_rng_alg, buf, len, 0));
}

// ─── ECDH ────────────────────────────────────────────────────────────────────

int whip_ecdh_generate_keypair(unsigned char* pubkey_out, unsigned char* privkey_out)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    DWORD blob_size = 0;
    unsigned char* blob = NULL;
    int success = 0;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0)))
        goto cleanup;

    if (!NT_SUCCESS(BCryptGenerateKeyPair(alg, &key, 256, 0)))
        goto cleanup;

    if (!NT_SUCCESS(BCryptFinalizeKeyPair(key, 0)))
        goto cleanup;

    if (!NT_SUCCESS(BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &blob_size, 0)))
        goto cleanup;

    blob = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, blob_size);
    if (!blob) goto cleanup;

    if (!NT_SUCCESS(BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, blob_size, &blob_size, 0)))
        goto cleanup;

    // BCRYPT_ECCKEY_BLOB: dwMagic(4) + cbKey(4) + X(32) + Y(32)
    if (blob_size >= 8 + 64) {
        memcpy(pubkey_out, blob + 8, 64);
    }

    DWORD priv_blob_size = 0;
    if (!NT_SUCCESS(BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &priv_blob_size, 0)))
        goto cleanup;

    unsigned char* priv_blob = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, priv_blob_size);
    if (!priv_blob) goto cleanup;

    if (!NT_SUCCESS(BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, priv_blob, priv_blob_size, &priv_blob_size, 0))) {
        HeapFree(GetProcessHeap(), 0, priv_blob);
        goto cleanup;
    }

    // BCRYPT_ECCKEY_BLOB: dwMagic(4) + cbKey(4) + X(32) + Y(32) + d(32)
    if (priv_blob_size >= 8 + 64 + 32) {
        memcpy(privkey_out, priv_blob + 8 + 64, 32);
    }

    HeapFree(GetProcessHeap(), 0, priv_blob);
    success = 1;

cleanup:
    if (blob) HeapFree(GetProcessHeap(), 0, blob);
    if (key) BCryptDestroyKey(key);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return success;
}

int whip_ecdh_compute_shared(const unsigned char* their_pubkey,
                              const unsigned char* our_privkey,
                              unsigned char* shared_secret_out)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE our_key = NULL;
    BCRYPT_KEY_HANDLE their_key = NULL;
    BCRYPT_SECRET_HANDLE secret = NULL;
    DWORD secret_size = 0;
    unsigned char* secret_buf = NULL;
    int success = 0;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0)))
        goto cleanup;

    // Import our private key
    DWORD priv_blob_size = 8 + 64 + 32;
    unsigned char* priv_blob = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, priv_blob_size);
    if (!priv_blob) goto cleanup;

    *(DWORD*)(priv_blob + 0) = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
    *(DWORD*)(priv_blob + 4) = 32;
    memcpy(priv_blob + 8 + 64, our_privkey, 32);

    if (!NT_SUCCESS(BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPRIVATE_BLOB, &our_key, priv_blob, priv_blob_size, 0))) {
        HeapFree(GetProcessHeap(), 0, priv_blob);
        goto cleanup;
    }
    HeapFree(GetProcessHeap(), 0, priv_blob);

    // Import their public key
    DWORD pub_blob_size = 8 + 64;
    unsigned char* pub_blob = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pub_blob_size);
    if (!pub_blob) goto cleanup;

    *(DWORD*)(pub_blob + 0) = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    *(DWORD*)(pub_blob + 4) = 32;
    memcpy(pub_blob + 8, their_pubkey, 64);

    if (!NT_SUCCESS(BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &their_key, pub_blob, pub_blob_size, 0))) {
        HeapFree(GetProcessHeap(), 0, pub_blob);
        goto cleanup;
    }
    HeapFree(GetProcessHeap(), 0, pub_blob);

    // Compute shared secret
    if (!NT_SUCCESS(BCryptSecretAgreement(our_key, their_key, &secret, 0)))
        goto cleanup;

    if (!NT_SUCCESS(BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &secret_size, 0)))
        goto cleanup;

    secret_buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, secret_size);
    if (!secret_buf) goto cleanup;

    if (!NT_SUCCESS(BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, NULL, secret_buf, secret_size, &secret_size, 0)))
        goto cleanup;

    if (secret_size >= WHIP_SHARED_SECRET_SIZE) {
        memcpy(shared_secret_out, secret_buf, WHIP_SHARED_SECRET_SIZE);
        success = 1;
    }

cleanup:
    if (secret_buf) {
        SecureZeroMemory(secret_buf, secret_size);
        HeapFree(GetProcessHeap(), 0, secret_buf);
    }
    if (secret) BCryptDestroySecret(secret);
    if (their_key) BCryptDestroyKey(their_key);
    if (our_key) BCryptDestroyKey(our_key);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return success;
}

// ─── HMAC-SHA256 ─────────────────────────────────────────────────────────────

int whip_hmac_sha256(const unsigned char* key, unsigned int key_len,
                     const unsigned char* data, unsigned int data_len,
                     unsigned char* hmac_out)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    DWORD hash_size = 0;
    DWORD result_len = 0;
    int success = 0;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        goto cleanup;

    if (!NT_SUCCESS(BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_size, sizeof(hash_size), &result_len, 0)))
        goto cleanup;

    if (hash_size != 32) goto cleanup;

    if (!NT_SUCCESS(BCryptCreateHash(alg, &hash, NULL, 0, (PUCHAR)key, key_len, 0)))
        goto cleanup;

    if (!NT_SUCCESS(BCryptHashData(hash, (PUCHAR)data, data_len, 0)))
        goto cleanup;

    if (!NT_SUCCESS(BCryptFinishHash(hash, hmac_out, hash_size, 0)))
        goto cleanup;

    success = 1;

cleanup:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return success;
}

// ─── Dérivation clé session ──────────────────────────────────────────────────

int whip_derive_session_key(const unsigned char* shared_secret,
                             const unsigned char* challenge,
                             unsigned char* session_key_out)
{
    // Simple KDF : session_key = HMAC-SHA256(shared_secret, "WhipPipe-Session" || challenge)
    unsigned char kdf_input[64];
    const char* label = "WhipPipe-Session";
    unsigned int label_len = 17;

    memcpy(kdf_input, label, label_len);
    memcpy(kdf_input + label_len, challenge, WHIP_CHALLENGE_SIZE);

    return whip_hmac_sha256(shared_secret, WHIP_SHARED_SECRET_SIZE,
                            kdf_input, label_len + WHIP_CHALLENGE_SIZE,
                            session_key_out);
}

// ─── ChaCha20-Poly1305 ───────────────────────────────────────────────────────

whip_crypto_ctx* whip_crypto_session_create(const unsigned char* session_key)
{
    whip_crypto_ctx* ctx = (whip_crypto_ctx*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(whip_crypto_ctx));
    if (!ctx) return NULL;

    memcpy(ctx->session_key_bytes, session_key, WHIP_SESSION_KEY_SIZE);
    ctx->nonce_counter = 0;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&ctx->chacha_alg, BCRYPT_CHACHA20_POLY1305_ALGORITHM, NULL, 0))) {
        HeapFree(GetProcessHeap(), 0, ctx);
        return NULL;
    }

    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(ctx->chacha_alg, &ctx->session_key,
                                                NULL, 0,
                                                (PUCHAR)ctx->session_key_bytes, WHIP_SESSION_KEY_SIZE, 0))) {
        BCryptCloseAlgorithmProvider(ctx->chacha_alg, 0);
        HeapFree(GetProcessHeap(), 0, ctx);
        return NULL;
    }

    return ctx;
}

int whip_encrypt_message(whip_crypto_ctx* ctx,
                          const unsigned char* plaintext,
                          unsigned int plaintext_len,
                          unsigned char* nonce_out,
                          unsigned char* ciphertext_out,
                          unsigned char* mac_out)
{
    if (!ctx || !plaintext || !nonce_out || !ciphertext_out || !mac_out)
        return 0;

    // Génère nonce unique (counter-based)
    ctx->nonce_counter++;
    memset(nonce_out, 0, WHIP_NONCE_SIZE);
    memcpy(nonce_out, &ctx->nonce_counter, sizeof(ctx->nonce_counter));

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce_out;
    authInfo.cbNonce = WHIP_NONCE_SIZE;
    authInfo.pbTag = mac_out;
    authInfo.cbTag = WHIP_MAC_SIZE;

    ULONG result_len = 0;
    if (!NT_SUCCESS(BCryptEncrypt(ctx->session_key,
                                   (PUCHAR)plaintext, plaintext_len,
                                   &authInfo,
                                   NULL, 0,
                                   ciphertext_out, plaintext_len,
                                   &result_len, 0)))
        return 0;

    return 1;
}

int whip_decrypt_message(whip_crypto_ctx* ctx,
                          const unsigned char* nonce,
                          const unsigned char* ciphertext,
                          unsigned int ciphertext_len,
                          const unsigned char* mac,
                          unsigned char* plaintext_out)
{
    if (!ctx || !nonce || !ciphertext || !mac || !plaintext_out)
        return 0;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = WHIP_NONCE_SIZE;
    authInfo.pbTag = (PUCHAR)mac;
    authInfo.cbTag = WHIP_MAC_SIZE;

    ULONG result_len = 0;
    if (!NT_SUCCESS(BCryptDecrypt(ctx->session_key,
                                   (PUCHAR)ciphertext, ciphertext_len,
                                   &authInfo,
                                   NULL, 0,
                                   plaintext_out, ciphertext_len,
                                   &result_len, 0)))
        return 0;

    return 1;
}