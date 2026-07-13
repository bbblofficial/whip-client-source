#include "util/Types.h"
#include <sstream>
#include <iomanip>
#include <random>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

bool SessionId::isValid() const noexcept {
    for (const auto& byte : data) {
        if (byte != 0) {
            return true;
        }
    }
    return false;
}

std::string SessionId::toString() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (const auto& byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

SessionId SessionId::generate() {
    SessionId id;

#ifdef _WIN32
    BCryptGenRandom(
        nullptr,
        id.data.data(),
        static_cast<ULONG>(id.data.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
#else
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);
    for (auto& byte : id.data) {
        byte = static_cast<Byte>(dis(gen));
    }
#endif

    return id;
}

SessionId SessionId::fromString(std::string_view str) {
    SessionId id;
    if (str.length() != id.data.size() * 2) {
        return id;
    }

    for (size_t i = 0; i < id.data.size(); ++i) {
        std::string byteStr(str.substr(i * 2, 2));
        id.data[i] = static_cast<Byte>(std::stoul(byteStr, nullptr, 16));
    }

    return id;
}

std::string RequestId::toString() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (const auto& byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

RequestId RequestId::generate() {
    RequestId id;

#ifdef _WIN32
    BCryptGenRandom(
        nullptr,
        id.data.data(),
        static_cast<ULONG>(id.data.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
#else
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);
    for (auto& byte : id.data) {
        byte = static_cast<Byte>(dis(gen));
    }
#endif

    return id;
}

Nonce Nonce::generate() {
    Nonce nonce;

#ifdef _WIN32
    BCryptGenRandom(
        nullptr,
        nonce.data.data(),
        static_cast<ULONG>(nonce.data.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
#else
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);
    for (auto& byte : nonce.data) {
        byte = static_cast<Byte>(dis(gen));
    }
#endif

    return nonce;
}

void SessionKey::clear() noexcept {
    volatile Byte* pKey = key.data();
    volatile Byte* pHmac = hmacKey.data();

    for (size_t i = 0; i < key.size(); ++i) {
        pKey[i] = 0;
    }

    for (size_t i = 0; i < hmacKey.size(); ++i) {
        pHmac[i] = 0;
    }
}