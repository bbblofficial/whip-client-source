#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <chrono>
#include <optional>
#include <span>

using Byte = uint8_t;
using Bytes = std::vector<Byte>;
using ByteView = std::span<const Byte>;

using Timestamp = std::chrono::system_clock::time_point;
using Duration = std::chrono::milliseconds;

struct SessionId {
    std::array<Byte, 16> data{};

    [[nodiscard]] bool isValid() const noexcept;
    [[nodiscard]] std::string toString() const;

    static SessionId generate();
    static SessionId fromString(std::string_view str);
};

struct RequestId {
    std::array<Byte, 16> data{};

    [[nodiscard]] std::string toString() const;

    static RequestId generate();
};

struct SessionKey {
    std::array<Byte, 32> key{};
    std::array<Byte, 32> hmacKey{};

    void clear() noexcept;
};

struct Nonce {
    std::array<Byte, 12> data{};

    static Nonce generate();
};

struct ConfigConstants {
    static constexpr Duration SESSION_TTL = std::chrono::minutes(15);
    static constexpr Duration HEARTBEAT_INTERVAL = std::chrono::seconds(30);
    static constexpr Duration HEARTBEAT_TIMEOUT = std::chrono::seconds(60);
    static constexpr Duration REQUEST_TIMEOUT = std::chrono::seconds(30);
    static constexpr int32_t TIMESTAMP_WINDOW_SECONDS = 30;
};