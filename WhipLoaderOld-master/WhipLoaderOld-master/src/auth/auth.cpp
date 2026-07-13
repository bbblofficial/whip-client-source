#include "auth.h"
#include "protocol/protocol.h"
#include "utils/NativeCrypto/Crypto/XorCrypto.h"
#include <chrono>
#include <random>
#include <cstring>

#include "mmap/core/mmap.h"

#ifdef Themida
#include "SecureEngineMacros.h"
#pragma optimize("", off)
#endif

Auth::Auth() : hwid(nullptr),
               authenticated(false),
               close(false),
               keysProvisioned(false) {
    // Initialize provisioned auth with embedded keys
    const ProvisionedKeyData* embeddedKeys = findEmbeddedKeys();
    if (embeddedKeys != nullptr) {
        keysProvisioned = provisionedAuth.init(embeddedKeys);
    }
}

long long Auth::getTimestamp() {
#ifdef Themida
    VM_TIGER_WHITE_START
#endif
    const auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count();
#ifdef Themida
    VM_TIGER_WHITE_END
#endif
}

void Auth::deriveSessionKey(
    const char* hwid,
    long long timestamp,
    const unsigned char* salt,
    unsigned char* session_key_out
) {
#ifdef Themida
    VM_FISH_WHITE_START
#endif

    const unsigned char master_key_hash[32] = {
        0x42, 0xb5, 0x21, 0x6a, 0x19, 0x72, 0x60, 0x58,
        0x15, 0x13, 0x11, 0xd3, 0xa9, 0xa7, 0xca, 0xc7,
        0xb4, 0x9d, 0x4c, 0x07, 0xda, 0x5a, 0xe6, 0x4e,
        0xb1, 0x93, 0x69, 0xef, 0x80, 0x1e, 0xa5, 0xab
    };

    size_t hwid_len = strlen(hwid);
    size_t key_material_size = 32 + hwid_len + 8 + 16;
    unsigned char* key_material = new unsigned char[key_material_size];

    size_t offset = 0;
    memcpy(key_material + offset, master_key_hash, 32);
    offset += 32;

    memcpy(key_material + offset, hwid, hwid_len);
    offset += hwid_len;

    unsigned char timestamp_bytes[8];
    memcpy(timestamp_bytes, &timestamp, 8);
    memcpy(key_material + offset, timestamp_bytes, 8);
    offset += 8;

    memcpy(key_material + offset, salt, 16);

    NativeCrypto::Crypto::hashSHA256(
        key_material,
        key_material_size,
        session_key_out
    );

    delete[] key_material;

#ifdef Themida
    VM_FISH_WHITE_END
#endif
}

bool Auth::verifyChecksum(
    const unsigned char* ciphertext, size_t ciphertext_len,
    const unsigned char* nonce, const unsigned char* salt,
    const unsigned char* tag, long long timestamp,
    const unsigned char* expected_checksum
) {
#ifdef Themida
    VM_DOLPHIN_RED_START
#endif

    size_t checksum_data_size = ciphertext_len + 12 + 16 + 16 + 8;
    unsigned char* checksum_data = new unsigned char[checksum_data_size];

    size_t offset = 0;
    memcpy(checksum_data + offset, ciphertext, ciphertext_len);
    offset += ciphertext_len;

    memcpy(checksum_data + offset, nonce, 12);
    offset += 12;

    memcpy(checksum_data + offset, salt, 16);
    offset += 16;

    memcpy(checksum_data + offset, tag, 16);
    offset += 16;

    unsigned char timestamp_bytes[8];
    memcpy(timestamp_bytes, &timestamp, 8);
    memcpy(checksum_data + offset, timestamp_bytes, 8);

    unsigned char computed_checksum[32];
    NativeCrypto::Crypto::hashSHA256(
        checksum_data,
        checksum_data_size,
        computed_checksum
    );

    bool result = memcmp(computed_checksum, expected_checksum, 32) == 0;

    delete[] checksum_data;

#ifdef Themida
    VM_DOLPHIN_RED_END
#endif

    return result;
}

void Auth::sendSecurityAlert(const char* detection_type, const char* details) {
#ifdef Themida
    VM_SHARK_RED_START
#endif

    SecureSocket alert_socket;

    if (!alert_socket.connect("82.22.77.15", 1323)) {
        return;
    }

    long long timestamp = getTimestamp();

    char alert_msg[2048];
    snprintf(alert_msg, sizeof(alert_msg),
        "action:security_alert|hwid:%s|detection:%s|details:%s|timestamp:%lld",
        getHwid(), detection_type, details, timestamp
    );

    size_t alert_len = strlen(alert_msg);
    const uint8_t* alert_data = reinterpret_cast<const uint8_t*>(alert_msg);

    alert_socket.sendMessage(MessageType::SECURITY_ALERT, alert_data, alert_len);

    alert_socket.disconnect();

#ifdef Themida
    VM_SHARK_RED_END
#endif
}

void Auth::reportThreat(const char* threat_type, const char* threat_details) {
#ifdef Themida
    VM_LION_WHITE_START
#endif

    if (!hwid) {
        return;
    }

    std::thread([this, threat_type, threat_details]() {
        const size_t type_len = strlen(threat_type);
        const size_t details_len = strlen(threat_details);

        char* type_copy = new char[type_len + 1];
        char* details_copy = new char[details_len + 1];

        memcpy(type_copy, threat_type, type_len);
        memcpy(details_copy, threat_details, details_len);
        type_copy[type_len] = '\0';
        details_copy[details_len] = '\0';

        sendSecurityAlert(type_copy, details_copy);

        NativeCrypto::Utils::memzero_safe(type_copy, type_len);
        NativeCrypto::Utils::memzero_safe(details_copy, details_len);
        delete[] type_copy;
        delete[] details_copy;
    }).detach();

#ifdef Themida
    VM_LION_WHITE_END
#endif
}

bool Auth::login(const char* hwid, unsigned char** dllBytes, size_t* dllSize) {
#ifdef Themida
    VM_TIGER_BLACK_START
#endif

    *dllBytes = nullptr;
    *dllSize = 0;

    this->hwid = hwid;

    if (!socket.connect("82.22.77.15", 1323)) {
        return false;
    }

    if (keysProvisioned && provisionedAuth.isInitialized()) {
        return loginWithProvisionedAuth(hwid, dllBytes, dllSize);
    }

    long long timestamp = getTimestamp();

#ifdef Themida
    VM_TIGER_BLACK_END
#endif

#ifdef Themida
    VM_MUTATE_ONLY_START
#endif

    unsigned char nonce[16];
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    *reinterpret_cast<uint64_t*>(nonce) = dis(gen);
    *reinterpret_cast<uint64_t*>(nonce + 8) = dis(gen);

    unsigned int request_nonce_b64_len;
    char* request_nonce_b64 = NativeCrypto::Crypto::encodeBase64(
        nonce, 16, &request_nonce_b64_len
    );

#ifdef Themida
    VM_MUTATE_ONLY_END
#endif

#ifdef Themida
    VM_EAGLE_RED_START
#endif

    const unsigned char master_key_hash[32] = {
        0x42, 0xb5, 0x21, 0x6a, 0x19, 0x72, 0x60, 0x58,
        0x15, 0x13, 0x11, 0xd3, 0xa9, 0xa7, 0xca, 0xc7,
        0xb4, 0x9d, 0x4c, 0x07, 0xda, 0x5a, 0xe6, 0x4e,
        0xb1, 0x93, 0x69, 0xef, 0x80, 0x1e, 0xa5, 0xab
    };

    size_t hwid_len = strlen(hwid);
    size_t challenge_material_size = 32 + hwid_len + 8 + 16;
    unsigned char* challenge_material = new unsigned char[challenge_material_size];

    size_t offset = 0;
    memcpy(challenge_material + offset, master_key_hash, 32);
    offset += 32;

    memcpy(challenge_material + offset, hwid, hwid_len);
    offset += hwid_len;

    unsigned char timestamp_bytes[8];
    memcpy(timestamp_bytes, &timestamp, 8);
    memcpy(challenge_material + offset, timestamp_bytes, 8);
    offset += 8;

    memcpy(challenge_material + offset, nonce, 16);

    unsigned char challenge_hash[32];
    NativeCrypto::Crypto::hashSHA256(
        challenge_material,
        challenge_material_size,
        challenge_hash
    );

    delete[] challenge_material;

#ifdef Themida
    VM_EAGLE_RED_END
#endif

#ifdef Themida
    VM_FISH_RED_START
#endif

    unsigned int challenge_b64_len;
    char* challenge_response = NativeCrypto::Crypto::encodeBase64(
        challenge_hash, 32, &challenge_b64_len
    );

    char request[4096];
    snprintf(request, sizeof(request),
        "action:login|hwid:%s|timestamp:%lld|nonce:%s|challenge:%s",
        hwid, timestamp, request_nonce_b64, challenge_response
    );

    size_t requestLen = strlen(request);
    const uint8_t* requestData = reinterpret_cast<const uint8_t*>(request);

    NativeCrypto::Crypto::freeBase64(request_nonce_b64);
    NativeCrypto::Crypto::freeBase64(challenge_response);
    NativeCrypto::Utils::memzero_safe(challenge_hash, 32);

#ifdef Themida
    VM_FISH_RED_END
#endif

#ifdef Themida
    VM_DOLPHIN_WHITE_START
#endif

    if (!socket.sendMessage(MessageType::LOADER_AUTH, requestData, requestLen)) {
        socket.disconnect();
        return false;
    }

    uint8_t* responsePayload = nullptr;
    size_t responsePayloadSize = 0;
    BinaryMessageHeader responseHeader{};

#ifdef Themida
    VM_DOLPHIN_WHITE_END
#endif

#ifdef Themida
    VM_FISH_WHITE_START
#endif

    if (!socket.receiveMessage(responseHeader, &responsePayload, &responsePayloadSize)) {
        return false;
    }

    const char* response_str = reinterpret_cast<const char*>(responsePayload);
    size_t response_len = responsePayloadSize;

    const char* last_checksum = nullptr;
    const char* temp = response_str;
    while ((temp = strstr(temp + 1, "|checksum:")) != nullptr) {
        last_checksum = temp;
    }

    if (!last_checksum) {
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    const char* checksum_value = last_checksum + 10;

    const char* last_timestamp = nullptr;
    temp = response_str;
    while ((temp = strstr(temp + 1, "|timestamp:")) != nullptr && temp < last_checksum) {
        last_timestamp = temp;
    }

    if (!last_timestamp) {
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    const char* timestamp_value = last_timestamp + 11;

    const char* last_tag = nullptr;
    temp = response_str;
    while ((temp = strstr(temp + 1, "|tag:")) != nullptr && temp < last_timestamp) {
        last_tag = temp;
    }

    if (!last_tag) {
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    const char* tag_value = last_tag + 5;

    const char* last_salt = nullptr;
    temp = response_str;
    while ((temp = strstr(temp + 1, "|salt:")) != nullptr && temp < last_tag) {
        last_salt = temp;
    }

    if (!last_salt) {
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    const char* salt_value = last_salt + 6;

    const char* last_nonce = nullptr;
    temp = response_str;
    while ((temp = strstr(temp + 1, "|nonce:")) != nullptr && temp < last_salt) {
        last_nonce = temp;
    }

    if (!last_nonce) {
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    const char* nonce_value = last_nonce + 7;

    const char* ciphertext_field = strstr(response_str, "|ciphertext:");
    if (!ciphertext_field) {
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    const char* ciphertext_value = ciphertext_field + 12;
    size_t ciphertext_b64_len = last_nonce - ciphertext_value;

    if (strncmp(response_str, "status:0", 8) != 0) {
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    char* ciphertext_b64 = new char[ciphertext_b64_len + 1];
    memcpy(ciphertext_b64, ciphertext_value, ciphertext_b64_len);
    ciphertext_b64[ciphertext_b64_len] = '\0';

    unsigned int ciphertext_len;
    unsigned char* ciphertext = NativeCrypto::Crypto::decodeBase64(
        ciphertext_b64, &ciphertext_len
    );
    delete[] ciphertext_b64;

    if (!ciphertext) {
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    size_t response_nonce_b64_len = last_salt - nonce_value;
    char* response_nonce_b64 = new char[response_nonce_b64_len + 1];
    memcpy(response_nonce_b64, nonce_value, response_nonce_b64_len);
    response_nonce_b64[response_nonce_b64_len] = '\0';

    unsigned int nonce_aes_len;
    unsigned char* nonce_aes = NativeCrypto::Crypto::decodeBase64(response_nonce_b64, &nonce_aes_len);
    delete[] response_nonce_b64;

    if (!nonce_aes || nonce_aes_len != 12) {
        NativeCrypto::Crypto::freeBase64(ciphertext);
        if (nonce_aes) NativeCrypto::Crypto::freeBase64(nonce_aes);
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    size_t response_salt_b64_len = last_tag - salt_value;
    char* response_salt_b64 = new char[response_salt_b64_len + 1];
    memcpy(response_salt_b64, salt_value, response_salt_b64_len);
    response_salt_b64[response_salt_b64_len] = '\0';

    unsigned int salt_len;
    unsigned char* salt = NativeCrypto::Crypto::decodeBase64(response_salt_b64, &salt_len);
    delete[] response_salt_b64;

    if (!salt || salt_len != 16) {
        NativeCrypto::Crypto::freeBase64(ciphertext);
        NativeCrypto::Crypto::freeBase64(nonce_aes);
        if (salt) NativeCrypto::Crypto::freeBase64(salt);
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    size_t response_tag_b64_len = last_timestamp - tag_value;
    char* response_tag_b64 = new char[response_tag_b64_len + 1];
    memcpy(response_tag_b64, tag_value, response_tag_b64_len);
    response_tag_b64[response_tag_b64_len] = '\0';

    unsigned int tag_len;
    unsigned char* tag = NativeCrypto::Crypto::decodeBase64(response_tag_b64, &tag_len);
    delete[] response_tag_b64;

    if (!tag || tag_len != 16) {
        NativeCrypto::Crypto::freeBase64(ciphertext);
        NativeCrypto::Crypto::freeBase64(nonce_aes);
        NativeCrypto::Crypto::freeBase64(salt);
        if (tag) NativeCrypto::Crypto::freeBase64(tag);
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    long long timestamp_server;
    sscanf(timestamp_value, "%lld", &timestamp_server);

    size_t response_checksum_b64_len = (response_str + response_len) - checksum_value;
    char* response_checksum_b64 = new char[response_checksum_b64_len + 1];
    memcpy(response_checksum_b64, checksum_value, response_checksum_b64_len);
    response_checksum_b64[response_checksum_b64_len] = '\0';

    for (size_t i = 0; i < response_checksum_b64_len; i++) {
        char c = response_checksum_b64[i];
        if (c == '=' || (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '+' || c == '/') {
            continue;
        }
        response_checksum_b64[i] = '\0';
        break;
    }

    unsigned int checksum_len;
    unsigned char* checksum = NativeCrypto::Crypto::decodeBase64(response_checksum_b64, &checksum_len);
    delete[] response_checksum_b64;

    if (!checksum || checksum_len != 32) {
        NativeCrypto::Crypto::freeBase64(ciphertext);
        NativeCrypto::Crypto::freeBase64(nonce_aes);
        NativeCrypto::Crypto::freeBase64(salt);
        NativeCrypto::Crypto::freeBase64(tag);
        if (checksum) NativeCrypto::Crypto::freeBase64(checksum);
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    bool success = false;
    unsigned char session_key[32] = {0};
    unsigned char aes_key[16] = {0};

    do {
        if (!verifyChecksum(ciphertext, ciphertext_len, nonce_aes, salt,
                           tag, timestamp_server, checksum)) {
            break;
        }

        deriveSessionKey(hwid, timestamp_server, salt, session_key);
        memcpy(aes_key, session_key, 16);

        size_t aad_data_size = hwid_len + 8 + salt_len;
        unsigned char* aad_data = new unsigned char[aad_data_size];

        offset = 0;
        memcpy(aad_data + offset, hwid, hwid_len);
        offset += hwid_len;

        unsigned char timestamp_bytes_aad[8];
        memcpy(timestamp_bytes_aad, &timestamp_server, 8);
        memcpy(aad_data + offset, timestamp_bytes_aad, 8);
        offset += 8;

        memcpy(aad_data + offset, salt, salt_len);

        delete[] aad_data;

        *dllSize = ciphertext_len;
        *dllBytes = new unsigned char[*dllSize];

        NativeCrypto::u32 size = static_cast<NativeCrypto::u32>(*dllSize);

#ifdef Themida
        VM_FISH_WHITE_END
#endif

        if (!NativeCrypto::Crypto::decryptXor(ciphertext, ciphertext_len, "WhipBETA31/10/2025", *dllBytes, &size)) {
            delete[] *dllBytes;
            *dllBytes = nullptr;
            *dllSize = 0;
            break;
        }

#ifdef Themida
        VM_FISH_WHITE_START
#endif

        *dllSize = size;

        success = true;
        authenticated.store(true);

    } while (false);

    NativeCrypto::Utils::memzero_safe(aes_key, 16);
    NativeCrypto::Utils::memzero_safe(session_key, 32);

    NativeCrypto::Crypto::freeBase64(ciphertext);
    NativeCrypto::Crypto::freeBase64(nonce_aes);
    NativeCrypto::Crypto::freeBase64(salt);
    NativeCrypto::Crypto::freeBase64(tag);
    NativeCrypto::Crypto::freeBase64(checksum);

    delete[] responsePayload;
    socket.disconnect();

    return success;

#ifdef Themida
    VM_FISH_WHITE_END
#endif
}

bool Auth::loginWithProvisionedAuth(const char* hwid, unsigned char** dllBytes, size_t* dllSize) {
#ifdef Themida
    VM_EAGLE_BLACK_START
#endif

    // Encode client ECDH public key
    const uint8_t* clientPubkey = provisionedAuth.getClientEcdhPublic();
    unsigned int pubkeyB64Len;
    char* pubkeyB64 = NativeCrypto::Crypto::encodeBase64(clientPubkey, 65, &pubkeyB64Len);

    // Send provisioned auth request
    char request[4096];
    snprintf(request, sizeof(request),
        "action:provisioned_login|hwid:%s|client_pubkey:%s",
        hwid, pubkeyB64
    );

    size_t requestLen = strlen(request);
    const uint8_t* requestData = reinterpret_cast<const uint8_t*>(request);

    if (!socket.sendMessage(MessageType::LOADER_AUTH, requestData, requestLen)) {
        NativeCrypto::Crypto::freeBase64(pubkeyB64);
        socket.disconnect();
        return false;
    }

    NativeCrypto::Crypto::freeBase64(pubkeyB64);

    // Receive response with session ID and server ECDH public key
    uint8_t* responsePayload = nullptr;
    size_t responsePayloadSize = 0;
    BinaryMessageHeader responseHeader{};

    if (!socket.receiveMessage(responseHeader, &responsePayload, &responsePayloadSize)) {
        socket.disconnect();
        return false;
    }

    const char* response_str = reinterpret_cast<const char*>(responsePayload);

    // Check status
    if (strncmp(response_str, "status:0", 8) != 0) {
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    // Parse session_id
    const char* sessionIdField = strstr(response_str, "|session_id:");
    if (!sessionIdField) {
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    const char* sessionIdValue = sessionIdField + 12;
    const char* serverPubkeyField = strstr(sessionIdValue, "|server_pubkey:");
    if (!serverPubkeyField) {
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    size_t sessionIdB64Len = serverPubkeyField - sessionIdValue;
    char* sessionIdB64 = new char[sessionIdB64Len + 1];
    memcpy(sessionIdB64, sessionIdValue, sessionIdB64Len);
    sessionIdB64[sessionIdB64Len] = '\0';

    unsigned int sessionIdLen;
    uint8_t* sessionId = NativeCrypto::Crypto::decodeBase64(sessionIdB64, &sessionIdLen);
    delete[] sessionIdB64;

    if (!sessionId || sessionIdLen != 32) {
        if (sessionId) NativeCrypto::Crypto::freeBase64(sessionId);
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    // Parse server_pubkey
    const char* serverPubkeyValue = serverPubkeyField + 15;
    const char* endOfResponse = response_str + responsePayloadSize;

    // Find the end of server_pubkey (next pipe or end of string)
    const char* nextPipe = strchr(serverPubkeyValue, '|');
    size_t serverPubkeyB64Len = nextPipe ? (nextPipe - serverPubkeyValue) : (endOfResponse - serverPubkeyValue);

    char* serverPubkeyB64 = new char[serverPubkeyB64Len + 1];
    memcpy(serverPubkeyB64, serverPubkeyValue, serverPubkeyB64Len);
    serverPubkeyB64[serverPubkeyB64Len] = '\0';

    unsigned int serverPubkeyLen;
    uint8_t* serverPubkey = NativeCrypto::Crypto::decodeBase64(serverPubkeyB64, &serverPubkeyLen);
    delete[] serverPubkeyB64;

    if (!serverPubkey || serverPubkeyLen != 65) {
        NativeCrypto::Crypto::freeBase64(sessionId);
        if (serverPubkey) NativeCrypto::Crypto::freeBase64(serverPubkey);
        delete[] responsePayload;
        socket.disconnect();
        return false;
    }

    delete[] responsePayload;

    // Start enforced session
    if (!provisionedAuth.startSession(sessionId, sessionIdLen, serverPubkey, serverPubkeyLen)) {
        NativeCrypto::Crypto::freeBase64(sessionId);
        NativeCrypto::Crypto::freeBase64(serverPubkey);
        socket.disconnect();
        return false;
    }

    NativeCrypto::Crypto::freeBase64(sessionId);
    NativeCrypto::Crypto::freeBase64(serverPubkey);

    // Request DLL download using enforced encryption
    const char* downloadReq = "action:download_dll";
    size_t downloadReqLen = strlen(downloadReq);

    uint8_t encryptedRequest[4096];
    size_t encryptedRequestLen = sizeof(encryptedRequest);

    if (!provisionedAuth.encryptEnforced(
        reinterpret_cast<const uint8_t*>(downloadReq), downloadReqLen,
        encryptedRequest, &encryptedRequestLen)) {
        socket.disconnect();
        return false;
    }

    if (!socket.sendMessage(MessageType::ENCRYPTED_PAYLOAD, encryptedRequest, encryptedRequestLen)) {
        socket.disconnect();
        return false;
    }

    // Receive encrypted DLL response
    uint8_t* encryptedPayload = nullptr;
    size_t encryptedPayloadSize = 0;
    BinaryMessageHeader dllHeader{};

    if (!socket.receiveMessage(dllHeader, &encryptedPayload, &encryptedPayloadSize)) {
        socket.disconnect();
        return false;
    }

    // Decrypt DLL using enforced decryption
    uint8_t* decryptedDll = new uint8_t[encryptedPayloadSize];
    size_t decryptedDllLen = encryptedPayloadSize;

    if (!provisionedAuth.decryptEnforced(encryptedPayload, encryptedPayloadSize,
                                         decryptedDll, &decryptedDllLen)) {
        delete[] encryptedPayload;
        delete[] decryptedDll;
        socket.disconnect();
        return false;
    }

    delete[] encryptedPayload;

    // Return decrypted DLL
    *dllBytes = decryptedDll;
    *dllSize = decryptedDllLen;

    authenticated.store(true);
    socket.disconnect();

#ifdef Themida
    VM_EAGLE_BLACK_END
#endif

    return true;
}

Auth* Auth::instance = nullptr;