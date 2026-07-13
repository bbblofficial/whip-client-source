#pragma once

#include "../util/Result.h"
#include "InjectionResult.h"
#include <vector>
#include <functional>
#include <memory>

using OnProcessFound = std::function<void(const ProcessInfo& process)>;
using OnProcessLost = std::function<void(uint32_t processId)>;

class ProcessFinder {
public:
    ProcessFinder();
    ~ProcessFinder();

    [[nodiscard]] Result<ProcessInfo> findByName(const std::string& processName);
    [[nodiscard]] Result<ProcessInfo> findByPid(uint32_t pid);
    [[nodiscard]] Result<std::vector<ProcessInfo>> findAllByName(const std::string& processName);

    // Find Java processes whose command line contains at least one of the keywords (case-insensitive).
    // If keywords is empty, returns all java/javaw processes.
    [[nodiscard]] Result<std::vector<ProcessInfo>> findJavaByKeyword(const std::vector<std::string>& keywords);
    [[nodiscard]] Result<std::vector<ProcessInfo>> findJavaByKeyword(const std::string& keyword);

    [[nodiscard]] Result<ProcessInfo> waitForProcess(
        const std::string& processName,
        Duration timeout
    );

    void startMonitoring(const std::string& processName, Duration checkInterval);
    void stopMonitoring();
    [[nodiscard]] bool isMonitoring() const noexcept;

    void setOnProcessFound(OnProcessFound callback);
    void setOnProcessLost(OnProcessLost callback);

    [[nodiscard]] bool isProcessRunning(uint32_t pid) const;
    [[nodiscard]] bool isProcessRunning(const std::string& name) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

[[nodiscard]] std::unique_ptr<ProcessFinder> createProcessFinder();
