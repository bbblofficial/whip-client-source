#pragma once
#include <whipnexus/Types.h>
#include <whipnexus/SyscallManager.h>
#include <new>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

enum class ErrorCode {

    NetworkError = 100,
    ConnectionFailed,
    ConnectionLost,
    SendFailed,
    ReceiveFailed,
    Timeout,

    AuthError = 200,
    InvalidCredentials,
    AccountLocked,
    SessionExpired,
    SessionInvalid,
    TooManySessions,

    LicenseError = 300,
    LicenseExpired,
    LicenseRevoked,
    NoLicense,
    NoMatchingProduct,

    ConfigError = 400,
    ConfigNotFound,
    ConfigPermissionDenied,

    FileError = 500,
    FileNotFound,
    FileDecryptFailed,

    ProtocolError = 600,
    InvalidPacket,
    InvalidSignature,
    VersionMismatch,

    Unknown = 999,
};

struct Error {
    ErrorCode code;
    String message;

    __forceinline bool isRetryable() const {
        int c = static_cast<int>(code);
        return (c >= 100 && c < 200) || code == ErrorCode::Timeout;
    }
};

template<typename T>
class Result {
private:
    bool hasValue_;
    union Storage {
        T value;
        Error error;
        __forceinline Storage() {}
        __forceinline ~Storage() {}
    } storage_;

public:
    __forceinline static Result ok(const T& val) {
        Result r;
        r.hasValue_ = true;
        new (&r.storage_.value) T(val);
        return r;
    }
    __forceinline static Result err(ErrorCode code, const char* msg) {
        Result r;
        r.hasValue_ = false;
        new (&r.storage_.error) Error{code, String(msg)};
        return r;
    }
    __forceinline Result() : hasValue_(false) {
        new (&storage_.error) Error{ErrorCode::Unknown, String("")};
    }
    __forceinline ~Result() {
        if (hasValue_) storage_.value.~T();
        else storage_.error.~Error();
    }
    __forceinline Result(const Result& other) : hasValue_(other.hasValue_) {
        if (hasValue_) new (&storage_.value) T(other.storage_.value);
        else new (&storage_.error) Error(other.storage_.error);
    }
    __forceinline Result& operator=(const Result& other) {
        if (this != &other) {
            this->~Result();
            hasValue_ = other.hasValue_;
            if (hasValue_) new (&storage_.value) T(other.storage_.value);
            else new (&storage_.error) Error(other.storage_.error);
        }
        return *this;
    }
    __forceinline bool isOk() const { return hasValue_; }
    __forceinline const T& value() const { return storage_.value; }
    __forceinline T& value() { return storage_.value; }
    __forceinline const Error& error() const { return storage_.error; }
};

class VoidResult {
private:
    bool hasError_;
    union Storage {
        char dummy;
        Error error;
        __forceinline Storage() : dummy(0) {}
        __forceinline ~Storage() {}
    } storage_;

public:
    __forceinline static VoidResult ok() {
        VoidResult r;
        r.hasError_ = false;
        return r;
    }
    __forceinline static VoidResult err(ErrorCode code, const char* msg) {
        VoidResult r;
        r.hasError_ = true;
        new (&r.storage_.error) Error{code, String(msg)};
        return r;
    }
    __forceinline VoidResult() : hasError_(false) {}
    __forceinline ~VoidResult() {
        if (hasError_) storage_.error.~Error();
    }
    __forceinline VoidResult(const VoidResult& other) : hasError_(other.hasError_) {
        if (hasError_) new (&storage_.error) Error(other.storage_.error);
    }
    __forceinline VoidResult& operator=(const VoidResult& other) {
        if (this != &other) {
            this->~VoidResult();
            hasError_ = other.hasError_;
            if (hasError_) new (&storage_.error) Error(other.storage_.error);
        }
        return *this;
    }
    __forceinline bool isOk() const { return !hasError_; }
    __forceinline const Error& error() const { return storage_.error; }
};

#pragma optimize("", on)
