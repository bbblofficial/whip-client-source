#pragma once

#include <string_view>
#include <memory>
#include <vector>
#include <source_location>
#include <format>

enum class LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4,
    Fatal = 5,
    None = 6
};

class ILogSink {
public:
    virtual ~ILogSink() = default;

    virtual void write(LogLevel level,
                       std::string_view message,
                       std::string_view category,
                       const std::source_location& location) = 0;

    virtual void flush() = 0;
};

class Logger {
public:
    static Logger& instance();

    void setLevel(LogLevel level);
    void addSink(std::shared_ptr<ILogSink> sink);
    void clearSinks();

    template<typename... Args>
    void log(LogLevel level,
             std::string_view category,
             std::format_string<Args...> fmt,
             Args&&... args) {
        if (level < minLevel_) return;
        auto message = std::format(fmt, std::forward<Args>(args)...);
        writeToSinks(level, message, category, std::source_location::current());
    }

    template<typename... Args>
    void trace(std::string_view cat, std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Trace, cat, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void debug(std::string_view cat, std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Debug, cat, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void info(std::string_view cat, std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Info, cat, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void warning(std::string_view cat, std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Warning, cat, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void error(std::string_view cat, std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Error, cat, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void fatal(std::string_view cat, std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Fatal, cat, fmt, std::forward<Args>(args)...);
    }

    void flush();

private:
    Logger() = default;

    void writeToSinks(LogLevel level,
                      std::string_view message,
                      std::string_view category,
                      const std::source_location& location);

    LogLevel minLevel_ = LogLevel::Info;
    std::vector<std::shared_ptr<ILogSink>> sinks_;
};

#define LOG_TRACE(cat, ...) Logger::instance().trace(cat, __VA_ARGS__)
#define LOG_DEBUG(cat, ...) Logger::instance().debug(cat, __VA_ARGS__)
#define LOG_INFO(cat, ...)  Logger::instance().info(cat, __VA_ARGS__)
#define LOG_WARN(cat, ...)  Logger::instance().warning(cat, __VA_ARGS__)
#define LOG_ERROR(cat, ...) Logger::instance().error(cat, __VA_ARGS__)
#define LOG_FATAL(cat, ...) Logger::instance().fatal(cat, __VA_ARGS__)

struct LogCategory {
    static constexpr auto Core = "Core";
    static constexpr auto Network = "Network";
    static constexpr auto Auth = "Auth";
    static constexpr auto License = "License";
    static constexpr auto Download = "Download";
    static constexpr auto Injection = "Injection";
    static constexpr auto IPC = "IPC";
    static constexpr auto Security = "Security";
    static constexpr auto UI = "UI";
    static constexpr auto Update = "Update";
};