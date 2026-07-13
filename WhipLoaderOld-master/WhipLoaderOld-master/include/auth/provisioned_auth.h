#pragma once

#include <cstdint>
#include <cstring>

// Patoke requirement: Server-provisioned keys embedded in binary
// Each deployed client has unique key material
#pragma pack(push, 1)
struct ProvisionedKeyData {
    uint8_t client_id[16];              // Unique per-client ID
    uint64_t issued_timestamp;          // Key generation time
    uint64_t expiry_timestamp;          // Expiration (0=never)

    // Pre-computed key material (server-generated)
    uint8_t base_secret[32];            // For session key derivation
    uint8_t time_secret[32];            // For time-based encryption
    uint8_t ecdh_seed[48];              // Deterministic ECDH seed
    uint8_t struct_seed[32];            // Per-client struct layout seed

    uint8_t server_ecdh_pubkey[65];     // Server's ECDH public key
    uint8_t server_signature[64];       // Signature proving authenticity
    uint32_t checksum;                  // Integrity verification
};
#pragma pack(pop)

// Enforced session state
struct EnforcedSessionState {
    uint8_t session_id[32];             // Server-assigned session ID
    uint8_t session_signing_key[32];    // Derived signing key
    uint64_t last_window_index;         // Anti-replay window tracking
    uint64_t message_counter;           // Anti-replay message counter
    bool active;                        // Encryption mandatory flag
};

// Provisioned auth context
class ProvisionedAuthContext {
private:
    bool initialized;
    bool keys_provisioned;
    ProvisionedKeyData keys;
    EnforcedSessionState enforced;
    uint8_t msg_type_mask;              // Per-client message type XOR mask

    // Derived keys
    uint8_t client_ecdh_private[32];    // Derived from ecdh_seed
    uint8_t client_ecdh_public[65];     // Derived public key
    uint8_t shared_secret[32];          // ECDH shared secret

public:
    ProvisionedAuthContext();
    ~ProvisionedAuthContext();

    // Initialization
    bool init(const ProvisionedKeyData* provisioned_keys);
    bool isInitialized() const { return initialized; }
    bool isKeysProvisioned() const { return keys_provisioned; }

    // Session establishment
    bool startSession(const uint8_t* session_id, size_t session_id_len,
                      const uint8_t* server_ecdh_pubkey, size_t pubkey_len);

    // Enforced encryption
    bool isEnforcedActive() const { return enforced.active; }
    bool encryptEnforced(const uint8_t* plaintext, size_t plaintext_len,
                         uint8_t* ciphertext, size_t* ciphertext_len);
    bool decryptEnforced(const uint8_t* ciphertext, size_t ciphertext_len,
                         uint8_t* plaintext, size_t* plaintext_len);

    // Signing
    bool sign(const uint8_t* message, size_t message_len,
              uint8_t* signature, size_t* signature_len);
    bool verify(const uint8_t* message, size_t message_len,
                const uint8_t* signature, size_t signature_len);

    // Message type masking (Patoke requirement)
    uint8_t getMsgTypeMask() const { return msg_type_mask; }
    uint8_t encodeType(uint8_t type) const { return type ^ msg_type_mask; }
    uint8_t decodeType(uint8_t encoded) const { return encoded ^ msg_type_mask; }

    // Getters
    const uint8_t* getClientEcdhPublic() const { return client_ecdh_public; }
    const uint8_t* getSessionId() const { return enforced.session_id; }

private:
    // Internal crypto operations
    void deriveEcdhKeypair();
    void deriveSharedSecret(const uint8_t* server_pubkey);
    void deriveSigningKey();
    void deriveMsgTypeMask();
    uint64_t getCurrentWindowIndex() const;
    bool validateTimeWindow(uint64_t window_index);

    // Secure cleanup
    void secureZero(void* ptr, size_t len);
};

// Helper functions for embedded key lookup
const ProvisionedKeyData* findEmbeddedKeys();
bool verifyKeyChecksum(const ProvisionedKeyData* keys);