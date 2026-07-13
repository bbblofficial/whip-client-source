#pragma once

#include "mmap/core/common.h"

class ErrorHandler {
public:
    ErrorHandler();
    ~ErrorHandler();

    void SetError(ErrorCode code, const std::string& message);
    void SetError(ErrorCode code, const std::string& message, DWORD winError);

    void SetLastWinError(ErrorCode code, const std::string& message);

    [[nodiscard]] ErrorInfo GetLastError() const;

    [[nodiscard]] std::string GetLastErrorMessage() const;

    [[nodiscard]] bool HasError() const;

    void ClearError();

private:
    ErrorInfo m_lastError;
    bool m_hasError;
};

class NameRandomizer {
public:
    NameRandomizer();
    ~NameRandomizer();

    [[nodiscard]] MemorySize GenerateRandomMemorySize(MemorySize baseSize, MemorySize maxPadding) const;

    void ApplyRandomTiming(uint32_t minMs, uint32_t maxMs) const;

private:
    [[nodiscard]] char GetRandomChar() const;
};