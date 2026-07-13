#pragma once

#include <variant>
#include <string>
#include <functional>

enum class ErrorCode {
    Success = 0,
    Unknown = 1,
    InvalidArgument = 2,
    Timeout = 3,
    Cancelled = 4,
    NotFound = 5,
    NotImplemented = 6,
    InvalidData = 7,
    InitializationError = 8,

    NetworkError = 100,
    ConnectionFailed = 101,
    ConnectionLost = 102,
    TlsHandshakeFailed = 103,
    CertificatePinningFailed = 104,
    SendFailed = 105,
    ReceiveFailed = 106,

    AuthError = 200,
    InvalidCredentials = 201,
    AccountLocked = 202,
    AccountBanned = 203,
    SessionExpired = 204,
    SessionInvalid = 205,
    TooManySessions = 206,
    RateLimited = 207,

    LicenseError = 300,
    LicenseInvalid = 301,
    LicenseExpired = 302,
    LicenseRevoked = 303,
    LicenseHwidMismatch = 304,
    NoLicense = 305,

    InjectionError = 400,
    ProcessNotFound = 401,
    ProcessAccessDenied = 402,
    AllocationFailed = 403,
    MappingFailed = 404,
    InjectionDetected = 405,

    IpcError = 500,
    IpcConnectionFailed = 501,
    IpcTimeout = 502,
    IpcProtocolError = 503,

    ProtocolError = 600,
    InvalidPacket = 601,
    InvalidSignature = 602,
    ReplayDetected = 603,
    VersionMismatch = 604,

    SecurityError = 700,
    IntegrityCheckFailed = 701,
    DebuggerDetected = 702,
    TamperingDetected = 703,
};

struct Error {
    ErrorCode code = ErrorCode::Unknown;
    std::string message;
    std::string details;

    Error() = default;
    Error(ErrorCode c, std::string msg = "", std::string det = "")
        : code(c), message(std::move(msg)), details(std::move(det)) {}

    [[nodiscard]] bool isNetworkError() const noexcept {
        return static_cast<int>(code) >= 100 && static_cast<int>(code) < 200;
    }

    [[nodiscard]] bool isAuthError() const noexcept {
        return static_cast<int>(code) >= 200 && static_cast<int>(code) < 300;
    }

    [[nodiscard]] bool isLicenseError() const noexcept {
        return static_cast<int>(code) >= 300 && static_cast<int>(code) < 400;
    }

    [[nodiscard]] bool isRetryable() const noexcept {
        switch (code) {
            case ErrorCode::Timeout:
            case ErrorCode::NetworkError:
            case ErrorCode::ConnectionLost:
            case ErrorCode::RateLimited:
                return true;
            default:
                return false;
        }
    }
};

template<typename T, typename E = Error>
class Result {
public:
    static Result ok(T value) {
        Result r;
        r.data_ = std::move(value);
        return r;
    }

    static Result err(E error) {
        Result r;
        r.data_ = std::move(error);
        return r;
    }

    static Result err(ErrorCode code, std::string message = "") {
        return err(E{code, std::move(message)});
    }

    [[nodiscard]] bool isOk() const noexcept {
        return std::holds_alternative<T>(data_);
    }

    [[nodiscard]] bool isErr() const noexcept {
        return std::holds_alternative<E>(data_);
    }

    explicit operator bool() const noexcept {
        return isOk();
    }

    [[nodiscard]] T& value() & { return std::get<T>(data_); }
    [[nodiscard]] const T& value() const& { return std::get<T>(data_); }
    [[nodiscard]] T&& value() && { return std::get<T>(std::move(data_)); }

    [[nodiscard]] E& error() & { return std::get<E>(data_); }
    [[nodiscard]] const E& error() const& { return std::get<E>(data_); }

    [[nodiscard]] T valueOr(T defaultValue) const& {
        return isOk() ? value() : std::move(defaultValue);
    }

    template<typename F>
    auto map(F&& f) -> Result<decltype(f(std::declval<T>())), E> {
        using U = decltype(f(std::declval<T>()));
        if (isOk()) return Result<U, E>::ok(f(value()));
        return Result<U, E>::err(error());
    }

    template<typename F>
    auto andThen(F&& f) -> decltype(f(std::declval<T>())) {
        if (isOk()) return f(value());
        return decltype(f(std::declval<T>()))::err(error());
    }

private:
    std::variant<T, E> data_;
};

template<typename E>
class Result<void, E> {
public:
    static Result ok() {
        Result r;
        r.isOk_ = true;
        return r;
    }

    static Result err(E error) {
        Result r;
        r.error_ = std::move(error);
        r.isOk_ = false;
        return r;
    }

    static Result err(ErrorCode code, std::string message = "") {
        return err(E{code, std::move(message)});
    }

    [[nodiscard]] bool isOk() const noexcept { return isOk_; }
    [[nodiscard]] bool isErr() const noexcept { return !isOk_; }
    explicit operator bool() const noexcept { return isOk_; }

    [[nodiscard]] const E& error() const& { return error_; }
    [[nodiscard]] E& error() & { return error_; }

private:
    E error_;
    bool isOk_ = false;
};

using VoidResult = Result<void, Error>;