#pragma once
#include <cstdint>
#include <ctime>
#include <chrono>
#include <cstdio>

#ifdef _WIN32
    #define _CRT_SECURE_NO_WARNINGS
#endif

class TimeUtils {
public:
    static uint64_t getUnixTimestamp() {
        return static_cast<uint64_t>(std::time(nullptr));
    }

    static long long currentTimeMillis() {
        const auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()
        ).count();
    }

    static const char* formatTime(const time_t& time) {
        static char timeBuffer[64];
        struct tm timeinfo;

#ifdef _WIN32
        errno_t err = gmtime_s(&timeinfo, &time);
        if (err != 0) {
            return "Invalid time";
        }
#else
        struct tm* result = gmtime_r(&time, &timeinfo);
        if (result == nullptr) {
            return "Invalid time";
        }
#endif

        size_t formatResult = strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S UTC", &timeinfo);
        if (formatResult == 0) {
            return "Time format error";
        }

        return timeBuffer;
    }

    static bool isTimeValid(const time_t& time) {
        struct tm timeinfo;
#ifdef _WIN32
        return gmtime_s(&timeinfo, &time) == 0;
#else
        return gmtime_r(&time, &timeinfo) != nullptr;
#endif
    }
};