#pragma once

#include "util/Result.h"
#include "network/WhipNexusClient.h"
#include "auth/Credentials.h"
#include "security/HWIDCollector.h"
#include "security/SecureMemory.h"
#include "injection/ProcessFinder.h"
#include "injection/InjectionResult.h"
#include "injection/ManualMapInjector.h"

#include <Windows.h>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

class FileDownloader;
class IConsoleUI;
class IEmbeddedDataReader;
class IHWIDCollector;
class LoaderIpcServer;

enum class LoaderStep {
    Idle,
    Initializing,
    WaitingForProcess,
    Connecting,
    Authenticating,
    FetchingLicenses,
    SelectingProduct,
    ValidatingLicense,
    DownloadingModule,
    Injecting,
    Running,
    Disconnecting,
    Error
};

struct LoaderContext {
    LoaderStep currentStep = LoaderStep::Idle;
    LoaderStep previousStep = LoaderStep::Idle;
    std::string statusMessage;
    int progressPercent = 0;
    std::optional<Error> lastError;
    bool canRetry = false;

    std::string username;
    std::vector<LoaderProductInfo> availableProducts;
    int selectedProductIndex = -1;
    std::string sessionToken;

    std::string authIdentifier;  // downloadId or HWID hash
    bool usingHwidFallback = false;
};

using OnLoaderStepChanged = std::function<void(const LoaderContext&)>;
using OnLoaderError = std::function<void(const Error&)>;
using OnLoaderComplete = std::function<void()>;

struct LoaderDependencies {
    IEmbeddedDataReader* embeddedDataReader = nullptr;
    IHWIDCollector* hwidCollector = nullptr;
    IConsoleUI* ui = nullptr;
};

class Loader {
public:
    Loader();
    ~Loader();

    Loader(const Loader&) = delete;
    Loader& operator=(const Loader&) = delete;

    void setDependencies(const LoaderDependencies& deps);

    [[nodiscard]] VoidResult initialize();
    void shutdown();
    [[nodiscard]] bool isInitialized() const noexcept;

    [[nodiscard]] VoidResult start();
    void stop();
    void retry();

    [[nodiscard]] LoaderStep currentStep() const noexcept;
    [[nodiscard]] const LoaderContext& context() const noexcept;
    [[nodiscard]] bool isRunning() const noexcept;

    void setOnStepChanged(OnLoaderStepChanged callback);
    void setOnError(OnLoaderError callback);
    void setOnComplete(OnLoaderComplete callback);

    void selectProduct(int index);

private:
    void transitionTo(LoaderStep step, const std::string& message = "", int percent = -1);
    void handleError(const Error& error, bool canRetry = false);

    void executeCurrentStep();
    void stepConnect();
    void stepAuthenticate();
    void stepFetchLicenses();
    void stepSelectProduct();
    void stepValidateLicense();
    void stepDownloadModule();
    void stepWaitForProcess();
    void stepInject();

    LoaderContext ctx;
    LoaderDependencies dependencies;

    OnLoaderStepChanged cbStepChanged;
    OnLoaderError cbError;
    OnLoaderComplete cbComplete;

    bool initialized;
    bool running;

    DownloadId downloadId;
    MachineInfo machineInfo;
    HWID hwid;

    ProcessInfo targetProcess;
    SecureBuffer moduleData;

    std::unique_ptr<WhipNexusClient> nexusClient;
    std::unique_ptr<LoaderIpcServer> ipcServer;
    uint16_t ipcPort;

    std::thread heartbeatThread;
    std::atomic<bool> heartbeatRunning;
    std::condition_variable heartbeatCV;
    std::mutex heartbeatMutex;

    std::thread processWatchThread;
    std::atomic<bool> processWatchRunning;

    std::unique_ptr<ManualMapInjector> injector;
    InjectionResult injectionResult;

    // Allow step files to access private members
    friend struct LoaderStepAccess;
};
