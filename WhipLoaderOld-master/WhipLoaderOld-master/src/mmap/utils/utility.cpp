#include "mmap/utils/utility.h"

#include <ctime>

ErrorHandler::ErrorHandler() : m_hasError(false) {
    m_lastError.code = ErrorCode::SUCCESS;
    m_lastError.message = "No error";
    m_lastError.lastWinError = 0;
}

ErrorHandler::~ErrorHandler() {
    m_hasError = false;
    m_lastError.code = ErrorCode::SUCCESS;
    m_lastError.message.clear();
    m_lastError.lastWinError = 0;
}

void ErrorHandler::SetError(ErrorCode code, const std::string& message) {
    m_lastError.code = code;
    m_lastError.message = message;
    m_lastError.lastWinError = 0;
    m_hasError = true;
}

void ErrorHandler::SetError(ErrorCode code, const std::string& message, DWORD winError) {
    m_lastError.code = code;
    m_lastError.message = message;
    m_lastError.lastWinError = winError;
    m_hasError = true;
}

void ErrorHandler::SetLastWinError(ErrorCode code, const std::string& message) {
    m_lastError.code = code;
    m_lastError.message = message;
    m_lastError.lastWinError = ::GetLastError();
    m_hasError = true;
}

ErrorInfo ErrorHandler::GetLastError() const {
    return m_lastError;
}

std::string ErrorHandler::GetLastErrorMessage() const {
    std::string errorMsg = m_lastError.message;

    if (m_lastError.lastWinError != 0) {
        char winErrorMsg[256] = { 0 };
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            m_lastError.lastWinError,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            winErrorMsg,
            sizeof(winErrorMsg),
            NULL
        );

        errorMsg += " (Windows Error: " + std::string(winErrorMsg) + ")";
    }

    return errorMsg;
}

bool ErrorHandler::HasError() const {
    return m_hasError;
}

void ErrorHandler::ClearError() {
    m_lastError.code = ErrorCode::SUCCESS;
    m_lastError.message = "No error";
    m_lastError.lastWinError = 0;
    m_hasError = false;
}

NameRandomizer::NameRandomizer() {
    srand(static_cast<unsigned int>(time(NULL)));
}

NameRandomizer::~NameRandomizer() {
}

MemorySize NameRandomizer::GenerateRandomMemorySize(MemorySize baseSize, MemorySize maxPadding) const {
    MemorySize padding = Utils::GetRandomNumber(0, (uint32_t)maxPadding);
    return baseSize + padding;
}

void NameRandomizer::ApplyRandomTiming(uint32_t minMs, uint32_t maxMs) const {
    Utils::RandomSleep(minMs, maxMs);
}

char NameRandomizer::GetRandomChar() const {
    static const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    return charset[Utils::GetRandomNumber(0, sizeof(charset) - 2)];
}