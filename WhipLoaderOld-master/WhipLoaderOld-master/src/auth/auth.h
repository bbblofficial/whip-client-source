#pragma once
#include "socket.h"
#include <thread>
#include <atomic>
#include <condition_variable>
#include <queue>
#include <future>
#include <cstdint>
#include <cstring>

#include "../../include/utils/hwidutils.h"
#include "../../include/auth/provisioned_auth.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

class Auth {
private:
    static Auth* instance;
    char username[32]{};
    const char* hwid;
    bool isRunning;
    SecureSocket socket;
    const char* IP;
    char currentTimestamp[64]{};
    char transportKey[64]{};

    std::atomic<bool> heartbeatRunning;
    std::atomic<bool> authenticated;
    std::atomic<bool> shouldShutdown;

    bool close;

    // Patoke-compliant provisioned auth
    ProvisionedAuthContext provisionedAuth;
    bool keysProvisioned;

    Auth();

    long long getTimestamp();

    void deriveSessionKey(const char* hwid, long long timestamp, const unsigned char* salt,
                          unsigned char* session_key_out);

    bool verifyChecksum(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* nonce,
                        const unsigned char* salt, const unsigned char* tag, long long timestamp,
                        const unsigned char* expected_checksum);

    void sendSecurityAlert(const char* detection_type, const char* details);

    bool loginWithProvisionedAuth(const char* hwid, unsigned char** dllBytes, size_t* dllSize);

public:
    static Auth* getInstance() {
        if (!instance)
            instance = new Auth();
        return instance;
    }

    bool login(const char* hwid, unsigned char** dllBytes, size_t* dllSize);

    void reportThreat(const char* threat_type, const char* threat_details);

    const char* getUsername() const {
        return username;
    }

    const char* getHwid() const {
        return hwid;
    }

    bool isAuthenticated() const {
        return !close;
    }

    bool shouldClientShutdown() const {
        return shouldShutdown;
    }
};