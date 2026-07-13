#pragma once

#include "../util/Result.h"

#include <memory>
#include <functional>

class IConsoleUI;
class Loader;

using OnApplicationExit = std::function<void(int exitCode)>;

class Application {
public:
    Application();
    ~Application();

    Application(const Application&) = delete;
    Application& operator=(const Application&) = delete;
    Application(Application&&) = delete;
    Application& operator=(Application&&) = delete;

    [[nodiscard]] VoidResult initialize();
    int run();
    void shutdown();

    void requestExit(int exitCode = 0);

    [[nodiscard]] IConsoleUI* ui() const;
    [[nodiscard]] Loader* loader() const;

    void setOnExit(OnApplicationExit callback);

private:
    void registerServices();
    void setupLoaderCallbacks();

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

[[nodiscard]] Application& app();
