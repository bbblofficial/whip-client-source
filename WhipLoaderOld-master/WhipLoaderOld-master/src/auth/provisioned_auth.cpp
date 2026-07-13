#include "auth/provisioned_auth.h"
#include "utils/NativeCrypto/NativeCrypto.h"
#include <chrono>
#include <cstring>

#include "auth.h"

#ifdef Themida
#include "SecureEngineMacros.h"
#pragma optimize("", off)
#endif

// Embedded provisioned keys (populated by server during deployment)
// In production, this would be in a separate section or encrypted
#pragma section(".pkeys", read)
__declspec(allocate(".pkeys"))
static ProvisionedKeyData g_embedded_keys = {0};
static bool g_keys_embedded = false;

ProvisionedAuthContext::ProvisionedAuthContext()
    : initialized(false), keys_provisioned(false), msg_type_mask(0) {
#ifdef Themida
    VM_TIGER_WHITE_START
#endif

    secureZero(&keys, sizeof(keys));
    secureZero(&enforced, sizeof(enforced));
    secureZero(client_ecdh_private, 32);
    secureZero(client_ecdh_public, 65);
    secureZero(shared_secret, 32);

#ifdef Themida
    VM_TIGER_WHITE_END
#endif
}

ProvisionedAuthContext::~ProvisionedAuthContext() {
#ifdef Themida
    VM_SHARK_WHITE_START
#endif

    // Secure cleanup
    secureZero(&keys, sizeof(keys));
    secureZero(&enforced, sizeof(enforced));
    secureZero(client_ecdh_private, 32);
    secureZero(client_ecdh_public, 65);
    secureZero(shared_secret, 32);

#ifdef Themida
    VM_SHARK_WHITE_END
#endif
}

bool ProvisionedAuthContext::init(const ProvisionedKeyData* provisioned_keys) {
#ifdef Themida
    VM_FISH_WHITE_START
#endif

    if (!provisioned_keys) {
        return false;
    }

    // Verify checksum
    if (!verifyKeyChecksum(provisioned_keys)) {
        return false;
    }

    // Check expiration
    if (provisioned_keys->expiry_timestamp != 0) {
        auto now = std::chrono::system_clock::now();
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();

        if (static_cast<uint64_t>(now_ms) > provisioned_keys->expiry_timestamp) {
            return false; // Keys expired
        }
    }

    // Copy keys
    memcpy(&keys, provisioned_keys, sizeof(ProvisionedKeyData));
    keys_provisioned = true;

    // Derive ECDH keypair from seed (deterministic)
    deriveEcdhKeypair();

    // Derive message type mask
    deriveMsgTypeMask();

    initialized = true;

#ifdef Themida
    VM_FISH_WHITE_END
#endif

    return true;
}

void ProvisionedAuthContext::deriveEcdhKeypair() {
#ifdef Themida
    VM_DOLPHIN_WHITE_START
#endif

    // Derive private key from ecdh_seed using HKDF
    const uint8_t info[] = "ecdh-private-key";
    NativeCrypto::Crypto::deriveKeyHKDF(
        keys.client_id, 16,          // salt
        keys.ecdh_seed, 48,           // ikm
        info, sizeof(info) - 1,       // info
        client_ecdh_private, 32       // okm
    );

    // Generate public key from private key using P256
    NativeCrypto::Crypto::deriveP256PublicKey(
        client_ecdh_private,
        client_ecdh_public
    );

#ifdef Themida
    VM_DOLPHIN_WHITE_END
#endif
}

void ProvisionedAuthContext::deriveMsgTypeMask() {
#ifdef Themida
    VM_MUTATE_ONLY_START
#endif

    // Derive XOR mask from struct_seed
    uint8_t mask_material[32];
    const uint8_t info[] = "msg-type-mask";
    NativeCrypto::Crypto::deriveKeyHKDF(
        keys.client_id, 16,          // salt
        keys.struct_seed, 32,         // ikm
        info, sizeof(info) - 1,       // info
        mask_material, 32             // okm
    );

    // Use first byte as mask
    msg_type_mask = mask_material[0];
    secureZero(mask_material, 32);

#ifdef Themida
    VM_MUTATE_ONLY_END
#endif
}

bool ProvisionedAuthContext::startSession(
    const uint8_t* session_id, size_t session_id_len,
    const uint8_t* server_ecdh_pubkey, size_t pubkey_len
) {
#ifdef Themida
    VM_TIGER_BLACK_START
#endif

    if (!initialized || session_id_len != 32 || pubkey_len != 65) {
        return false;
    }

    // Store session ID
    memcpy(enforced.session_id, session_id, 32);

    // Compute shared secret via ECDH
    deriveSharedSecret(server_ecdh_pubkey);

    // Derive signing key
    deriveSigningKey();

    // Initialize anti-replay counters
    enforced.last_window_index = 0;
    enforced.message_counter = 0;

    // Activate enforced encryption
    enforced.active = true;

#ifdef Themida
    VM_TIGER_BLACK_END
#endif

    return true;
}

void ProvisionedAuthContext::deriveSharedSecret(const uint8_t* server_pubkey) {
#ifdef Themida
    VM_EAGLE_WHITE_START
#endif

    // Perform ECDH: shared_secret = ECDH(client_private, server_public)
    NativeCrypto::Crypto::computeP256SharedSecret(
        client_ecdh_private,
        server_pubkey,
        shared_secret
    );

#ifdef Themida
    VM_EAGLE_WHITE_END
#endif
}

void ProvisionedAuthContext::deriveSigningKey() {
#ifdef Themida
    VM_LION_WHITE_START
#endif

    // signing_key = HKDF(time_secret, session_id, "signing-key")
    const uint8_t info[] = "signing-key";
    uint8_t info_with_session[11 + 32];
    memcpy(info_with_session, info, 11);
    memcpy(info_with_session + 11, enforced.session_id, 32);

    NativeCrypto::Crypto::deriveKeyHKDF(
        enforced.session_id, 32,      // salt
        keys.time_secret, 32,          // ikm
        info_with_session, 11 + 32,    // info
        enforced.session_signing_key, 32  // okm
    );

#ifdef Themida
    VM_LION_WHITE_END
#endif
}

uint64_t ProvisionedAuthContext::getCurrentWindowIndex() const {
#ifdef Themida
    VM_MUTATE_ONLY_START
#endif

    // 30-second windows like TOTP
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    uint64_t window = seconds / 30;

#ifdef Themida
    VM_MUTATE_ONLY_END
#endif

    return window;
}

bool ProvisionedAuthContext::validateTimeWindow(uint64_t window_index) {
#ifdef Themida
    VM_SHARK_RED_START
#endif

    uint64_t current = getCurrentWindowIndex();

    // Allow ±1 window tolerance for clock skew
    if (window_index < current - 1 || window_index > current + 1) {
        return false;
    }

    // Anti-replay: must be >= last used
    if (window_index < enforced.last_window_index) {
        return false;
    }

    enforced.last_window_index = window_index;

#ifdef Themida
    VM_SHARK_RED_END
#endif

    return true;
}

bool ProvisionedAuthContext::encryptEnforced(
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* ciphertext, size_t* ciphertext_len
) {
#ifdef Themida
    VM_FISH_BLACK_START
#endif

    if (!enforced.active) {
        return false;
    }

    // Format: [session_signature:32][window_index:8][counter:8][iv:12][ciphertext:N][tag:16]
    uint64_t window_index = getCurrentWindowIndex();

    // Derive time-based key for this window
    uint8_t time_key[32];
    uint8_t window_bytes[8];
    memcpy(window_bytes, &window_index, 8);

    const uint8_t info[] = "time-window-key";
    NativeCrypto::Crypto::hkdfSHA256(
        keys.time_secret, 32,
        window_bytes, 8,
        info, sizeof(info) - 1,
        time_key, 32
    );

    // Generate IV
    uint8_t iv[12];
    NativeCrypto::Crypto::randomBytes(iv, 12);

    // Encrypt with AES-256-GCM
    size_t encrypted_len = plaintext_len + 16; // + auth tag
    uint8_t* encrypted = new uint8_t[encrypted_len];

    if (!NativeCrypto::Crypto::aesGcmEncrypt(
        plaintext, plaintext_len,
        time_key, 32,
        iv, 12,
        encrypted, &encrypted_len
    )) {
        delete[] encrypted;
        secureZero(time_key, 32);
        return false;
    }

    // Build message signature: HMAC(signing_key, window_index || counter || ciphertext)
    uint8_t sig_data[8 + 8 + encrypted_len];
    size_t offset = 0;
    memcpy(sig_data + offset, &window_index, 8);
    offset += 8;
    memcpy(sig_data + offset, &enforced.message_counter, 8);
    offset += 8;
    memcpy(sig_data + offset, encrypted, encrypted_len);

    uint8_t session_signature[32];
    NativeCrypto::Crypto::hmacSHA256(
        enforced.session_signing_key, 32,
        sig_data, sizeof(sig_data),
        session_signature
    );

    // Build final message
    offset = 0;
    memcpy(ciphertext + offset, session_signature, 32);
    offset += 32;
    memcpy(ciphertext + offset, &window_index, 8);
    offset += 8;
    memcpy(ciphertext + offset, &enforced.message_counter, 8);
    offset += 8;
    memcpy(ciphertext + offset, iv, 12);
    offset += 12;
    memcpy(ciphertext + offset, encrypted, encrypted_len);
    offset += encrypted_len;

    *ciphertext_len = offset;

    // Increment counter
    enforced.message_counter++;

    // Cleanup
    delete[] encrypted;
    secureZero(time_key, 32);
    secureZero(iv, 12);

#ifdef Themida
    VM_FISH_BLACK_END
#endif

    return true;
}

bool ProvisionedAuthContext::decryptEnforced(
    const uint8_t* ciphertext, size_t ciphertext_len,
    uint8_t* plaintext, size_t* plaintext_len
) {
#ifdef Themida
    VM_DOLPHIN_BLACK_START
#endif

    if (!enforced.active || ciphertext_len < 32 + 8 + 8 + 12 + 16) {
        return false;
    }

    // Parse message
    size_t offset = 0;
    uint8_t session_signature[32];
    memcpy(session_signature, ciphertext + offset, 32);
    offset += 32;

    uint64_t window_index;
    memcpy(&window_index, ciphertext + offset, 8);
    offset += 8;

    uint64_t message_counter;
    memcpy(&message_counter, ciphertext + offset, 8);
    offset += 8;

    uint8_t iv[12];
    memcpy(iv, ciphertext + offset, 12);
    offset += 12;

    size_t encrypted_len = ciphertext_len - offset;
    const uint8_t* encrypted = ciphertext + offset;

    // Verify signature
    uint8_t sig_data[8 + 8 + encrypted_len];
    size_t sig_offset = 0;
    memcpy(sig_data + sig_offset, &window_index, 8);
    sig_offset += 8;
    memcpy(sig_data + sig_offset, &message_counter, 8);
    sig_offset += 8;
    memcpy(sig_data + sig_offset, encrypted, encrypted_len);

    uint8_t computed_signature[32];
    NativeCrypto::Crypto::hmacSHA256(
        enforced.session_signing_key, 32,
        sig_data, sizeof(sig_data),
        computed_signature
    );

    if (memcmp(session_signature, computed_signature, 32) != 0) {
        return false; // Invalid signature
    }

    // Validate time window
    if (!validateTimeWindow(window_index)) {
        return false; // Replay attack or clock skew
    }

    // Derive time-based key
    uint8_t time_key[32];
    uint8_t window_bytes[8];
    memcpy(window_bytes, &window_index, 8);

    const uint8_t info[] = "time-window-key";
    NativeCrypto::Crypto::hkdfSHA256(
        keys.time_secret, 32,
        window_bytes, 8,
        info, sizeof(info) - 1,
        time_key, 32
    );

    // Decrypt
    size_t decrypted_len = encrypted_len - 16; // - auth tag
    if (!NativeCrypto::Crypto::aesGcmDecrypt(
        encrypted, encrypted_len,
        time_key, 32,
        iv, 12,
        plaintext, &decrypted_len
    )) {
        secureZero(time_key, 32);
        return false;
    }

    *plaintext_len = decrypted_len;

    // Cleanup
    secureZero(time_key, 32);

#ifdef Themida
    VM_DOLPHIN_BLACK_END
#endif

    return true;
}

bool ProvisionedAuthContext::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
#ifdef Themida
    VM_EAGLE_BLACK_START
#endif

    if (!initialized || !keys_provisioned) {
        return false;
    }

    // Hash message
    uint8_t message_hash[32];
    NativeCrypto::Crypto::hashSHA256(message, message_len, message_hash);

    // Sign with ECDSA
    bool result = NativeCrypto::Crypto::p256Sign(
        client_ecdh_private,
        message_hash,
        signature
    );

    if (result) {
        *signature_len = 64; // P-256 signature is 64 bytes (r || s)
    }

    secureZero(message_hash, 32);

#ifdef Themida
    VM_EAGLE_BLACK_END
#endif

    return result;
}

bool ProvisionedAuthContext::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
#ifdef Themida
    VM_LION_BLACK_START
#endif

    if (!initialized || signature_len != 64) {
        return false;
    }

    // Hash message
    uint8_t message_hash[32];
    NativeCrypto::Crypto::hashSHA256(message, message_len, message_hash);

    // Verify with server's public key
    bool result = NativeCrypto::Crypto::p256Verify(
        keys.server_ecdh_pubkey,
        message_hash,
        signature
    );

    secureZero(message_hash, 32);

#ifdef Themida
    VM_LION_BLACK_END
#endif

    return result;
}

void ProvisionedAuthContext::secureZero(void* ptr, size_t len) {
    NativeCrypto::Utils::memzero_safe(ptr, len);
}

// Helper functions
const ProvisionedKeyData* findEmbeddedKeys() {
    if (g_keys_embedded) {
        return &g_embedded_keys;
    }
    return nullptr;
}

bool verifyKeyChecksum(const ProvisionedKeyData* keys) {
    if (!keys) {
        return false;
    }

    // Compute checksum over all fields except checksum itself
    uint8_t computed_checksum[32];
    NativeCrypto::Crypto::hashSHA256(
        reinterpret_cast<const uint8_t*>(keys),
        sizeof(ProvisionedKeyData) - sizeof(uint32_t),
        computed_checksum
    );

    // Use first 4 bytes as checksum
    uint32_t checksum = *reinterpret_cast<const uint32_t*>(computed_checksum);
    return checksum == keys->checksum;
}

Auth* Auth::instance = nullptr;