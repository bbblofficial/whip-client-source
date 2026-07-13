#include "mmap/core/common.h"
#include <thread>

namespace Utils {
    std::wstring StringToWideString(const std::string& str) {
        if (str.empty()) {
            return std::wstring();
        }

        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
        std::wstring wstr(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
        return wstr;
    }

    std::string WideStringToString(const std::wstring& wstr) {
        if (wstr.empty()) {
            return std::string();
        }

        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
        return str;
    }

    uint32_t GetRandomNumber(uint32_t min, uint32_t max) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(min, max);
        return dist(gen);
    }

    void RandomSleep(uint32_t minMs, uint32_t maxMs) {
        uint32_t sleepTime = GetRandomNumber(minMs, maxMs);
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
    }

    bool IsProcess64Bit(ProcessHandle hProcess) {
        BOOL isWow64 = FALSE;

#ifdef ARCH_X64
        if (IsWow64Process(hProcess, &isWow64)) {
            return !isWow64;
        }
#else
        return false;
#endif

#ifdef ARCH_X64
        return true;
#else
        return false;
#endif
    }

    void SecureZeroMemory(void* ptr, size_t size) {
        volatile char* p = (volatile char*)ptr;
        while (size--) {
            *p++ = 0;
        }
    }
}