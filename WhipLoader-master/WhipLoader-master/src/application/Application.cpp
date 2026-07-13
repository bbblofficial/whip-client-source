#pragma optimize("", off)
#include "application/Application.h"
#include "ui/IConsoleUI.h"
#ifdef WHIP_UI_IMGUI
#include "ui/ImGuiUIImpl.h"
#else
#include "ui/ConsoleUIImpl.h"
#endif
#include "loader/Loader.h"
#include "security/HWIDCollector.h"
#include "security/EmbeddedData.h"
#include <Windows.h>
#include <thread>
#include <chrono>
#include <exception>
#include <atomic>

struct Application::Impl {
#ifdef WHIP_UI_IMGUI
    std::unique_ptr<ImGuiUIImpl> consoleUI;
#else
    std::unique_ptr<ConsoleUIImpl> consoleUI;
#endif
    std::unique_ptr<Loader> loader;
    IHWIDCollector* hwidCollector = nullptr;
    IEmbeddedDataReader* embeddedDataReader = nullptr;

    OnApplicationExit onExit;

    int requestedExitCode = 0;
    bool exitRequested = false;
    bool initialized = false;
};

Application::Application() {
    impl_ = std::make_unique<Impl>();
}

Application::~Application() = default;

VoidResult Application::initialize() {
    registerServices();

    if (impl_->consoleUI) {
        auto uiResult = impl_->consoleUI->initialize();
        if (!uiResult) {
            return uiResult;
        }
    }

    if (impl_->loader) {
        auto wfResult = impl_->loader->initialize();
        if (!wfResult) {
            return wfResult;
        }
    }

    setupLoaderCallbacks();

    impl_->initialized = true;
    return VoidResult::ok();
}

int Application::run() {
    if (!impl_->initialized) {
        return 1;
    }

    auto* uiPtr = ui();
    if (uiPtr) {
        uiPtr->showBanner();
    }

    auto* wf = impl_->loader.get();
    if (wf) {
        try {
            uiPtr->showProgress("Starting workflow...", 0);

            auto startResult = wf->start();
            if (!startResult) {
                if (uiPtr) {
                    uiPtr->showError("Failed to start workflow: " + startResult.error().message);
                }
            } else {
                while (wf->isRunning() && !impl_->exitRequested) {
                    MSG msg;
                    if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                        TranslateMessage(&msg);
                        DispatchMessage(&msg);
                    }
                    Sleep(10);
                }
            }
        } catch (const std::exception& e) {
            if (uiPtr) {
                uiPtr->showError(std::string("Unexpected error: ") + e.what());
            }
        } catch (...) {
            if (uiPtr) {
                uiPtr->showError("Unknown fatal error occurred");
            }
        }
    }

#ifdef WHIP_UI_IMGUI
    if (uiPtr && !impl_->exitRequested) {
        uiPtr->waitForKey("Close");
    }
#endif

    return impl_->requestedExitCode;
}

void Application::shutdown() {
    if (impl_->loader) {
        impl_->loader->shutdown();
    }

    if (impl_->consoleUI) {
        impl_->consoleUI->shutdown();
    }

    impl_->initialized = false;
}

void Application::requestExit(int exitCode) {
    impl_->requestedExitCode = exitCode;
    impl_->exitRequested = true;

    if (impl_->onExit) {
        impl_->onExit(exitCode);
    }
}

IConsoleUI* Application::ui() const {
    return impl_->consoleUI.get();
}

Loader* Application::loader() const {
    return impl_->loader.get();
}

void Application::setOnExit(OnApplicationExit callback) {
    impl_->onExit = std::move(callback);
}

void Application::registerServices() {
#ifdef WHIP_UI_IMGUI
    impl_->consoleUI = std::make_unique<ImGuiUIImpl>();
#else
    impl_->consoleUI = std::make_unique<ConsoleUIImpl>();
#endif

    impl_->loader = std::make_unique<Loader>();
    impl_->hwidCollector = createHWIDCollector();
    impl_->embeddedDataReader = createEmbeddedDataReader();

    LoaderDependencies deps{};
    deps.hwidCollector = impl_->hwidCollector;
    deps.embeddedDataReader = impl_->embeddedDataReader;
    deps.ui = impl_->consoleUI.get();
    impl_->loader->setDependencies(deps);
}

void Application::setupLoaderCallbacks() {
    auto* wf = impl_->loader.get();
    auto* uiPtr = impl_->consoleUI.get();

    if (!wf || !uiPtr) return;

    wf->setOnStepChanged([uiPtr](const LoaderContext& ctx) {
        uiPtr->showProgress(ctx.statusMessage, ctx.progressPercent);
    });

    wf->setOnError([uiPtr](const Error& error) {
        uiPtr->hideProgress();
        uiPtr->showError(error.message);
        uiPtr->hideWindow();
#ifndef WHIP_BYPASS_MODE
        TerminateProcess(GetCurrentProcess(), 1);
#endif
    });

    wf->setOnComplete([uiPtr]() {
        uiPtr->showSuccess("Ready!");
    });
}

// Manual-mapped DLLs cannot rely on MSVC's function-local-static guard byte:
// when the image is loaded via SEC_IMAGE, the guard byte's *runtime* state
// drifts from the on-disk initial value (observed: ctor silently skipped,
// `static Application instance;` returns a zero-initialized object → impl_
// null → AV on first deref). Use a heap-allocated singleton with our own
// init barrier instead — no compiler-generated guards anywhere on this path.
Application& app() {
    static std::atomic<Application*> g_instance{nullptr};
    Application* p = g_instance.load(std::memory_order_acquire);
    if (!p) {
        Application* fresh = new Application();
        Application* expected = nullptr;
        if (g_instance.compare_exchange_strong(expected, fresh,
                                               std::memory_order_acq_rel)) {
            p = fresh;
        } else {
            delete fresh;
            p = expected;
        }
    }
    return *p;
}

#pragma optimize("", on)
