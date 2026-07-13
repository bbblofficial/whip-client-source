#pragma once

#include "../util/Result.h"
#include "../security/SecureMemory.h"
#include "InjectionResult.h"
#include "ProcessFinder.h"
#include <memory>
#include <functional>

struct InjectionOptions {
    bool eraseHeaders = false;          // Headers nécessaires pour SEH/exception handling du thread DLL
    bool executeTlsCallbacks = true;    // Exécuter TLS callbacks
    bool randomizeBaseAddress = false;  // Scatter mapping casse les refs RIP-relative entre sections
    bool resolveDelayedImports = true;  // Résoudre delayed imports
    Duration timeout = std::chrono::seconds(30);
};

using OnInjectionProgress = std::function<void(const std::string& stage, int percent)>;
using OnInjectionComplete = std::function<void(const InjectionResult& result)>;

class ManualMapInjector {
public:
    ManualMapInjector();
    ~ManualMapInjector();

    [[nodiscard]] Result<InjectionResult> inject(
        uint32_t processId,
        const SecureBuffer& dllData,
        const InjectionOptions& options = {}
    );

    [[nodiscard]] Result<InjectionResult> inject(
        const ProcessInfo& process,
        const SecureBuffer& dllData,
        const InjectionOptions& options = {}
    );

    void injectAsync(
        uint32_t processId,
        const SecureBuffer& dllData,
        const InjectionOptions& options,
        OnInjectionComplete onComplete,
        OnInjectionProgress onProgress = nullptr
    );

    [[nodiscard]] VoidResult unload(
        uint32_t processId,
        uintptr_t baseAddress
    );

    [[nodiscard]] bool isInjected() const noexcept;

    [[nodiscard]] const InjectionResult* lastResult() const;

    void setOnProgress(OnInjectionProgress callback);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

[[nodiscard]] std::unique_ptr<ManualMapInjector> createInjector();
