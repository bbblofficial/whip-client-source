#pragma once

#include "IConsoleUI.h"
#include "../util/Result.h"

#include <memory>

class ConsoleUIImpl : public IConsoleUI {
public:
    ConsoleUIImpl();
    ~ConsoleUIImpl() override;

    ConsoleUIImpl(const ConsoleUIImpl&) = delete;
    ConsoleUIImpl& operator=(const ConsoleUIImpl&) = delete;

    [[nodiscard]] VoidResult initialize();
    void shutdown();
    [[nodiscard]] bool isInitialized() const noexcept;

    void showBanner() override;
    void clearScreen() override;

    void showStatus(const std::string& message) override;
    void showSuccess(const std::string& message) override;
    void showError(const std::string& message) override;
    void showInfo(const std::string& message) override;
    void showWarning(const std::string& message) override;

    void showProgress(const std::string& message, int percent) override;
    void hideProgress() override;

    void showMenu(const std::string& title, const std::vector<MenuItem>& items) override;
    int waitForMenuSelection(int minId, int maxId) override;
    int showArrowSelectionMenu(const std::vector<MenuItem>& items) override;

    std::string waitForInput(const std::string& prompt) override;
    void waitForKey(const std::string& message) override;

    void setOnMenuSelected(OnMenuSelected callback) override;

    void hideWindow() override;
    void showWindow() override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
