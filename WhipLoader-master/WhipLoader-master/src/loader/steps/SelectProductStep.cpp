#pragma optimize("", off)
#include "loader/Loader.h"
#include "application/Application.h"
#include "network/WhipNexusClient.h"
#include "ipc/LoaderIpcServer.h"
#include "ui/IConsoleUI.h"
#include "injection/ManualMapInjector.h"
#include "security/ReverseDetector.h"

#include <Windows.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <string>

void Loader::stepSelectProduct() {
    if (ctx.selectedProductIndex >= 0) {
        const auto& selectedProduct = ctx.availableProducts[ctx.selectedProductIndex];

        auto selectResult = nexusClient->selectProduct(selectedProduct.code, machineInfo.pcName, machineInfo.executablePath);
        if (!selectResult) {
            auto shots = ReverseDetector::captureScreen();
            const char* dlId   = (!ctx.usingHwidFallback && !ctx.authIdentifier.empty())
                                 ? ctx.authIdentifier.c_str() : nullptr;
            const char* hwidPtr = hwid.hash[0] ? hwid.hash : nullptr;
            nexusClient->sendConnectFailReport("", &shots, dlId, hwidPtr);
            handleError(Error(ErrorCode::NetworkError, selectResult.error().message), true);
            return;
        }

        char sessionToken[65];
        nexusClient->getSessionToken(sessionToken, sizeof(sessionToken));
        ctx.sessionToken = sessionToken;

        ipcServer = std::make_unique<LoaderIpcServer>();
        auto initResult = ipcServer->initialize();
        if (!initResult) {
            handleError(Error(ErrorCode::InitializationError, "IPC init failed"), false);
            return;
        }

        static Loader* s_loaderForCallbacks = nullptr;
        s_loaderForCallbacks = this;

        static auto onLoadProgressCallback = [](const ClientLoadProgress* progress) {
            if (!s_loaderForCallbacks || !s_loaderForCallbacks->dependencies.ui || !progress) return;

            int loaderPercent = 40 + static_cast<int>(progress->percent * 0.6);
            s_loaderForCallbacks->dependencies.ui->showProgress(progress->message, loaderPercent);

            bool isComplete = (strstr(progress->message, "Client loaded") != nullptr) || (progress->percent >= 100);
            if (isComplete) {
                std::thread([ui = s_loaderForCallbacks->dependencies.ui]() {
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                    ui->hideProgress();
                    ui->hideWindow();
                }).detach();
            }
        };

        static auto onHeartbeatCallback = [](const ClientHeartbeatInfo* info) {
            (void)info;
        };

        static std::atomic<bool> s_exitOnce{false};
        static auto onDestructCallback = [](ClientDestructReason reason, const char* message) {
            if (s_exitOnce.exchange(true)) return;
            (void)reason;
            (void)message;

            if (s_loaderForCallbacks && s_loaderForCallbacks->dependencies.ui) {
                s_loaderForCallbacks->dependencies.ui->showWindow();
                s_loaderForCallbacks->dependencies.ui->showProgress("Destructing client...", 0);
            }

            Loader* ldr = s_loaderForCallbacks;
            if (ldr && ldr->injector && ldr->injector->isInjected()) {
                ldr->injector->unload(
                    ldr->injectionResult.processId,
                    ldr->injectionResult.baseAddress
                );
            }

            app().requestExit(0);
        };

        ipcServer->setOnLoadProgress(onLoadProgressCallback);
        ipcServer->setOnHeartbeat(onHeartbeatCallback);
        ipcServer->setOnDestruct(onDestructCallback);

        auto startResult = ipcServer->start();
        if (!startResult) {
            handleError(Error(ErrorCode::NetworkError, "Failed to start IPC server: " + startResult.error().message), false);
            return;
        }

        ipcPort = ipcServer->getPort();

        transitionTo(LoaderStep::ValidatingLicense, "Validating license...");
    }
}
#pragma optimize("", on)
