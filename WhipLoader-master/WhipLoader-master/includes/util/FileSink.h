#pragma once

#include "Logger.h"
#include <fstream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>

class FileSink : public ILogSink {
public:
    explicit FileSink(const std::string& filename) {
        file_.open(filename, std::ios::out | std::ios::app);
        if (!file_.is_open()) {
            // Fallback: try in current directory
            file_.open("loader.log", std::ios::out | std::ios::app);
        }
    }

    ~FileSink() override {
        if (file_.is_open()) {
            file_.close();
        }
    }

    void write(LogLevel level,
               std::string_view message,
               std::string_view category,
               const std::source_location& location) override {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!file_.is_open()) return;

        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::tm tm;
        localtime_s(&tm, &time);

        file_ << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
              << '.' << std::setfill('0') << std::setw(3) << ms.count()
              << " [" << getLevelString(level) << "]"
              << " [" << category << "] "
              << message << std::endl;
    }

    void flush() override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) {
            file_.flush();
        }
    }

private:
    static const char* getLevelString(LogLevel level) {
        switch (level) {
            case LogLevel::Trace:   return "TRACE";
            case LogLevel::Debug:   return "DEBUG";
            case LogLevel::Info:    return "INFO ";
            case LogLevel::Warning: return "WARN ";
            case LogLevel::Error:   return "ERROR";
            case LogLevel::Fatal:   return "FATAL";
            default:                return "NONE ";
        }
    }

    std::ofstream file_;
    std::mutex mutex_;
};