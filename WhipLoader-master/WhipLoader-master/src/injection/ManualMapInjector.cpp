#pragma optimize("", off)
#include "injection/ManualMapInjector.h"
#include <ManualMapper/ManualMapper.h>
#include <chrono>

struct ManualMapInjector::Impl {
    ManualMapper::ManualMapper mapper;
    InjectionResult lastResult;
    OnInjectionProgress onProgress;
    bool injected = false;

    void reportProgress(const std::string& stage, int percent) {
        if (onProgress) {
            onProgress(stage, percent);
        }
    }
};

ManualMapInjector::ManualMapInjector() : impl_(std::make_unique<Impl>()) {}

ManualMapInjector::~ManualMapInjector() = default;

Result<InjectionResult> ManualMapInjector::inject(
    uint32_t processId,
    const SecureBuffer& dllData,
    const InjectionOptions& /*options*/
) {
    InjectionResult result;
    result.processId = processId;
    result.startTime = std::chrono::system_clock::now();

    impl_->reportProgress("Loading image from memory", 10);

    if (!impl_->mapper.LoadImageFromMemory(dllData.data(), dllData.size())) {
        result.status = InjectionStatus::MappingFailed;
        result.errorMessage = "Failed to load PE image from memory";
        result.endTime = std::chrono::system_clock::now();
        result.duration = std::chrono::duration_cast<Duration>(result.endTime - result.startTime);
        impl_->lastResult = result;
        return Result<InjectionResult>::err(ErrorCode::InvalidArgument, result.errorMessage);
    }

    impl_->reportProgress("Mapping to process", 30);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        DWORD lastError = GetLastError();
        result.status = InjectionStatus::MappingFailed;
        result.errorMessage = "Failed to open target process (error: " + std::to_string(lastError) + ")";
        result.endTime = std::chrono::system_clock::now();
        result.duration = std::chrono::duration_cast<Duration>(result.endTime - result.startTime);
        impl_->lastResult = result;
        return Result<InjectionResult>::err(ErrorCode::InjectionError, result.errorMessage);
    }
    CloseHandle(hProcess);

    if (!impl_->mapper.MapToProcess(processId)) {
        result.status = InjectionStatus::MappingFailed;
        result.errorMessage = "Failed to map DLL to target process";
        result.endTime = std::chrono::system_clock::now();
        result.duration = std::chrono::duration_cast<Duration>(result.endTime - result.startTime);
        impl_->lastResult = result;
        return Result<InjectionResult>::err(ErrorCode::InjectionError, result.errorMessage);
    }

    auto ctx = impl_->mapper.GetContext();
    result.baseAddress = reinterpret_cast<uintptr_t>(ctx.remoteImageBase);

    if (!ctx.remoteImageBase) {
        result.status = InjectionStatus::MappingFailed;
        result.errorMessage = "Remote image base is NULL after mapping";
        result.endTime = std::chrono::system_clock::now();
        result.duration = std::chrono::duration_cast<Duration>(result.endTime - result.startTime);
        impl_->lastResult = result;
        return Result<InjectionResult>::err(ErrorCode::InjectionError, result.errorMessage);
    }

    impl_->reportProgress("Executing DllMain", 70);

    if (!impl_->mapper.Execute()) {
        result.status = InjectionStatus::EntryPointFailed;
        result.errorMessage = "Failed to execute DllMain";
        result.endTime = std::chrono::system_clock::now();
        result.duration = std::chrono::duration_cast<Duration>(result.endTime - result.startTime);
        impl_->lastResult = result;
        return Result<InjectionResult>::err(ErrorCode::InjectionError, result.errorMessage);
    }

    result.status = InjectionStatus::Success;
    result.entryPoint = reinterpret_cast<uintptr_t>(ctx.entryPoint);
    result.endTime = std::chrono::system_clock::now();
    result.duration = std::chrono::duration_cast<Duration>(result.endTime - result.startTime);

    impl_->lastResult = result;
    impl_->injected = true;
    impl_->reportProgress("Injection complete", 100);

    return Result<InjectionResult>::ok(result);
}

Result<InjectionResult> ManualMapInjector::inject(
    const ProcessInfo& process,
    const SecureBuffer& dllData,
    const InjectionOptions& options
) {
    return inject(process.processId, dllData, options);
}

void ManualMapInjector::injectAsync(
    uint32_t processId,
    const SecureBuffer& dllData,
    const InjectionOptions& options,
    OnInjectionComplete onComplete,
    OnInjectionProgress onProgress
) {
    if (onProgress) {
        impl_->onProgress = onProgress;
    }

    auto result = inject(processId, dllData, options);
    if (onComplete) {
        if (result.isOk()) {
            onComplete(result.value());
        } else {
            InjectionResult failedResult;
            failedResult.status = InjectionStatus::Unknown;
            failedResult.errorMessage = result.error().message;
            onComplete(failedResult);
        }
    }
}

VoidResult ManualMapInjector::unload(uint32_t processId, uintptr_t baseAddress) {
    (void)processId;
    (void)baseAddress;
    if (!impl_->injected) {
        return VoidResult::err(ErrorCode::InvalidArgument, "Nothing to unload");
    }

    if (!impl_->mapper.Unload()) {
        return VoidResult::err(ErrorCode::InjectionError, "Failed to unload DLL");
    }

    impl_->injected = false;
    return VoidResult::ok();
}

bool ManualMapInjector::isInjected() const noexcept {
    return impl_ && impl_->injected;
}

const InjectionResult* ManualMapInjector::lastResult() const {
    return impl_ ? &impl_->lastResult : nullptr;
}

void ManualMapInjector::setOnProgress(OnInjectionProgress callback) {
    if (impl_) {
        impl_->onProgress = std::move(callback);
    }
}

std::unique_ptr<ManualMapInjector> createInjector() {
    return std::make_unique<ManualMapInjector>();
}

#pragma optimize("", on)
