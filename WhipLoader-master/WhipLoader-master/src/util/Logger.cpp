#include "util/Logger.h"

Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

void Logger::setLevel(LogLevel level) {
    minLevel_ = level;
}

void Logger::addSink(std::shared_ptr<ILogSink> sink) {
    if (sink) {
        sinks_.push_back(std::move(sink));
    }
}

void Logger::clearSinks() {
    sinks_.clear();
}

void Logger::writeToSinks(LogLevel level,
                          std::string_view message,
                          std::string_view category,
                          const std::source_location& location) {
    for (auto& sink : sinks_) {
        sink->write(level, message, category, location);
    }
}

void Logger::flush() {
    for (auto& sink : sinks_) {
        sink->flush();
    }
}
