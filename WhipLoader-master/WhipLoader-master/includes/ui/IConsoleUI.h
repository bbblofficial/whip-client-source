#pragma once

#include <string>
#include <vector>
#include <functional>

struct MenuItem {
    int id;
    std::string label;
    std::string description;
};

using OnMenuSelected = std::function<void(int selectedId)>;
using OnInputReceived = std::function<void(const std::string& input)>;

class IConsoleUI {
public:
    virtual ~IConsoleUI() = default;

    virtual void showBanner() = 0;
    virtual void clearScreen() = 0;

    virtual void showStatus(const std::string& message) = 0;
    virtual void showSuccess(const std::string& message) = 0;
    virtual void showError(const std::string& message) = 0;
    virtual void showInfo(const std::string& message) = 0;
    virtual void showWarning(const std::string& message) = 0;

    virtual void showProgress(const std::string& message, int percent) = 0;
    virtual void hideProgress() = 0;

    virtual void showMenu(const std::string& title, const std::vector<MenuItem>& items) = 0;
    virtual int waitForMenuSelection(int minId, int maxId) = 0;
    virtual int showArrowSelectionMenu(const std::vector<MenuItem>& items) = 0;

    virtual std::string waitForInput(const std::string& prompt) = 0;
    virtual void waitForKey(const std::string& message = "Press any key to continue...") = 0;

    virtual void setOnMenuSelected(OnMenuSelected callback) = 0;

    virtual void hideWindow() {}
    virtual void showWindow() {}
};
