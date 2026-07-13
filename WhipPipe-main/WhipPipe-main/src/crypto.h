#ifndef WHIPPIPE_CRYPTO_H
#define WHIPPIPE_CRYPTO_H

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#define WHIP_ECDH_PUBKEY_SIZE   64   // ECDH P-256 public key
#define WHIP_ECDH_PRIVKEY_SIZE  32   // ECDH P-256 private key
#define WHIP_SHARED_SECRET_SIZE 32   // ECDH shared secret
#define WHIP_CHALLENGE_SIZE     32   // Challenge aléatoire
#define WHIP_RESPONSE_SIZE      32   // HMAC-SHA256 response
#define WHIP_SESSION_KEY_SIZE   32   // ChaCha20 key
#define WHIP_NONCE_SIZE         12   // ChaCha20-Poly1305 nonce
#define WHIP_MAC_SIZE           16   // Poly1305 MAC

typedef struct whip_crypto_ctx whip_crypto_ctx;

// ─── Initialisation ──────────────────────────────────────────────────────────

whip_crypto_ctx* whip_crypto_init(void);
void             whip_crypto_destroy(whip_crypto_ctx* ctx);

// ─── Génération aléatoire ────────────────────────────────────────────────────

int whip_random_bytes(unsigned char* buf, unsigned int len);

// ─── ECDH (Elliptic Curve Diffie-Hellman) ────────────────────────────────────

int whip_ecdh_generate_keypair(unsigned char* pubkey_out,   // 64 bytes
                                unsigned char* privkey_out); // 32 bytes

int whip_ecdh_compute_shared(const unsigned char* their_pubkey,  // 64 bytes
                              const unsigned char* our_privkey,   // 32 bytes
                              unsigned char* shared_secret_out);  // 32 bytes

// ─── HMAC-SHA256 ─────────────────────────────────────────────────────────────

int whip_hmac_sha256(const unsigned char* key, unsigned int key_len,
                     const unsigned char* data, unsigned int data_len,
                     unsigned char* hmac_out);  // 32 bytes

// ─── Dérivation clé session ──────────────────────────────────────────────────

int whip_derive_session_key(const unsigned char* shared_secret,  // 32 bytes
                             const unsigned char* challenge,      // 32 bytes
                             unsigned char* session_key_out);     // 32 bytes

// ─── ChaCha20-Poly1305 AEAD ──────────────────────────────────────────────────

whip_crypto_ctx* whip_crypto_session_create(const unsigned char* session_key);

int whip_encrypt_message(whip_crypto_ctx* ctx,
                          const unsigned char* plaintext,
                          unsigned int plaintext_len,
                          unsigned char* nonce_out,        // 12 bytes
                          unsigned char* ciphertext_out,   // plaintext_len bytes
                          unsigned char* mac_out);         // 16 bytes

int whip_decrypt_message(whip_crypto_ctx* ctx,
                          const unsigned char* nonce,      // 12 bytes
                          const unsigned char* ciphertext,
                          unsigned int ciphertext_len,
                          const unsigned char* mac,        // 16 bytes
                          unsigned char* plaintext_out);

#endif