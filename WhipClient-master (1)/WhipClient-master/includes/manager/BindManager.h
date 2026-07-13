#pragma once

#include <unordered_map>
#include <vector>
#include <memory>
#include "../bind/IBind.h"
#include "../bind/BindType.h"
#include "../util/Debug.h"

class BindManager {
public:
    BindManager() = default;

    void onInputPress(int keyCode);
    void onInputRelease(int keyCode);

    void registerBind(int keyCode, BindType bindType, std::function<void()> onActivated, std::function<void()> onDeactivated = nullptr);
    void removeBind(int keyCode);
    void removeBindForModule(void* modulePtr, int keyCode);
    void registerBindForModule(void* modulePtr, int keyCode, BindType bindType, std::function<void()> onActivated, std::function<void()> onDeactivated = nullptr);

    void syncBindStateForModule(void* modulePtr, bool active);

    void registerCallback(int keyCode, std::function<void()> onPress, std::function<void()> onRelease = nullptr);

    void registerCallbackForOwner(void* owner, int keyCode, std::function<void()> onPress, std::function<void()> onRelease = nullptr);

    void removeCallbackForOwner(void* owner, int keyCode);

    void removeCallback(int keyCode) {
        pressCallbacks.erase(keyCode);
        releaseCallbacks.erase(keyCode);
        ownerCallbacks.erase(keyCode);
    }

    void cleanup() {
        binds.clear();
        moduleBinds.clear();
        pressCallbacks.clear();
        releaseCallbacks.clear();
        ownerCallbacks.clear();
    }

    ~BindManager() = default;
    BindManager(const BindManager&) = delete;
    BindManager& operator=(const BindManager&) = delete;

    static BindManager& getInstance();

    bool hasKeyBind(int keyCode) const {
        auto it = binds.find(keyCode);
        bool hasModuleBinds = (it != binds.end() && !it->second.empty());

        return hasModuleBinds
            || pressCallbacks.find(keyCode) != pressCallbacks.end()
            || ownerCallbacks.find(keyCode) != ownerCallbacks.end();
    }

private:
    struct OwnerCallback {
        void* owner;
        std::function<void()> onPress;
        std::function<void()> onRelease;
    };

    struct ModuleBind {
        void* modulePtr;
        std::shared_ptr<IBind> bind;
    };

    std::unordered_map<int, std::vector<ModuleBind>> binds;
    std::unordered_map<void*, int> moduleBinds;

    std::unordered_map<int, std::vector<std::function<void()>>> pressCallbacks;
    std::unordered_map<int, std::vector<std::function<void()>>> releaseCallbacks;

    std::unordered_map<int, std::vector<OwnerCallback>> ownerCallbacks;
};
