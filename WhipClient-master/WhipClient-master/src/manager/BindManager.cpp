
#include "../../includes/manager/BindManager.h"
#include "../../includes/bind/impl/HoldBind.h"
#include "../../includes/bind/impl/ToggleBind.h"
#include "gui/Gui.h"
#include "../../includes/util/JNIUtils.h"
#include "../../includes/handler/ProviderHandler.h"
#include "../../includes/provider/impl/GameStateProvider.h"
#include "util/JniScope.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include <algorithm>

static bool isChatOpen() {

    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState) return false;

    if (!gameState->hasAnyScreen()) return false;

    if (!gameState->inGameHasFocus()
        && !gameState->isChestOpen()
        && !gameState->isInventoryOpen()) {
        return true;
    }

    return gameState->isChatOpen();
}

void BindManager::onInputPress(const int keyCode) {
    if (const auto it = binds.find(keyCode); it != binds.end()) {
        if (Gui::getInstance().isOpen()) {
            return;
        }

        if (isChatOpen()) {
            return;
        }

        for (auto& moduleBind : it->second) {
            moduleBind.bind->onKeyPress();
        }
    }

    if (const auto it = pressCallbacks.find(keyCode); it != pressCallbacks.end()) {
        if (Gui::getInstance().isOpen()) {
            return;
        }

        if (isChatOpen()) {
            return;
        }

        for (auto& callback : it->second) {
            callback();
        }
    }

    if (const auto it = ownerCallbacks.find(keyCode); it != ownerCallbacks.end()) {
        if (Gui::getInstance().isOpen()) {
            return;
        }

        if (isChatOpen()) {
            return;
        }

        for (auto& ownerCallback : it->second) {
            if (ownerCallback.onPress) {
                ownerCallback.onPress();
            }
        }
    }
}

void BindManager::onInputRelease(const int keyCode) {
    if (Gui::getInstance().isOpen()) {
        return;
    }

    if (isChatOpen()) {
        return;
    }

    if (const auto it = binds.find(keyCode); it != binds.end()) {
        for (auto& moduleBind : it->second) {
            moduleBind.bind->onKeyRelease();
        }
    }

    if (const auto it = releaseCallbacks.find(keyCode); it != releaseCallbacks.end()) {
        for (auto& callback : it->second) {
            callback();
        }
    }

    if (const auto it = ownerCallbacks.find(keyCode); it != ownerCallbacks.end()) {
        for (auto& ownerCallback : it->second) {
            if (ownerCallback.onRelease) {
                ownerCallback.onRelease();
            }
        }
    }
}

void BindManager::registerBind(const int keyCode, const BindType bindType, std::function<void()> onActivated, std::function<void()> onDeactivated) {
    removeBind(keyCode);

    std::shared_ptr<IBind> bind;

    switch (bindType) {
        case BindType::HOLD:
            bind = std::make_shared<HoldBind>(keyCode);
            break;
        case BindType::TOGGLE:
            bind = std::make_shared<ToggleBind>(keyCode);
            break;
        default:
            bind = std::make_shared<ToggleBind>(keyCode);
            break;
    }

    if (onActivated) {
        bind->setOnActivated(std::move(onActivated));
    }

    if (onDeactivated) {
        bind->setOnDeactivated(std::move(onDeactivated));
    }

    ModuleBind moduleBind;
    moduleBind.modulePtr = nullptr;
    moduleBind.bind = bind;
    binds[keyCode].push_back(moduleBind);
}

void BindManager::removeBind(const int keyCode) {
    binds.erase(keyCode);
}

void BindManager::removeBindForModule(void* modulePtr, const int keyCode) {

    if (const auto it = moduleBinds.find(modulePtr); it != moduleBinds.end()) {
        const int oldKeyCode = it->second;

        auto bindsIt = binds.find(oldKeyCode);
        if (bindsIt != binds.end()) {
            auto& moduleBindsVec = bindsIt->second;
            moduleBindsVec.erase(
                std::remove_if(moduleBindsVec.begin(), moduleBindsVec.end(),
                    [modulePtr](const ModuleBind& mb) { return mb.modulePtr == modulePtr; }),
                moduleBindsVec.end()
            );

            if (moduleBindsVec.empty()) {
                binds.erase(bindsIt);
            }
        }

        moduleBinds.erase(it);
    }
}

void BindManager::registerBindForModule(void* modulePtr, const int keyCode, const BindType bindType, std::function<void()> onActivated, std::function<void()> onDeactivated) {
    removeBindForModule(modulePtr, keyCode);

    if (keyCode == 0) return;

    std::shared_ptr<IBind> bind;

    switch (bindType) {
        case BindType::HOLD:
            bind = std::make_shared<HoldBind>(keyCode);
            break;
        case BindType::TOGGLE:
            bind = std::make_shared<ToggleBind>(keyCode);
            break;
        default:
            bind = std::make_shared<ToggleBind>(keyCode);
            break;
    }

    if (onActivated) {
        bind->setOnActivated(std::move(onActivated));
    }

    if (onDeactivated) {
        bind->setOnDeactivated(std::move(onDeactivated));
    }

    ModuleBind moduleBind;
    moduleBind.modulePtr = modulePtr;
    moduleBind.bind = bind;
    binds[keyCode].push_back(moduleBind);

    moduleBinds[modulePtr] = keyCode;
}

void BindManager::syncBindStateForModule(void* modulePtr, bool active) {
    if (const auto it = moduleBinds.find(modulePtr); it != moduleBinds.end()) {
        const int keyCode = it->second;
        if (const auto bindIt = binds.find(keyCode); bindIt != binds.end()) {

            for (auto& moduleBind : bindIt->second) {
                if (moduleBind.modulePtr == modulePtr) {
                    moduleBind.bind->setActive(active);
                    break;
                }
            }
        }
    }
}

void BindManager::registerCallback(const int keyCode, std::function<void()> onPress, std::function<void()> onRelease) {
    if (onPress) {
        pressCallbacks[keyCode].clear();
        pressCallbacks[keyCode].push_back(std::move(onPress));
    }

    if (onRelease) {
        releaseCallbacks[keyCode].clear();
        releaseCallbacks[keyCode].push_back(std::move(onRelease));
    }
}

void BindManager::registerCallbackForOwner(void* owner, const int keyCode, std::function<void()> onPress, std::function<void()> onRelease) {

    removeCallbackForOwner(owner, keyCode);

    OwnerCallback ownerCallback;
    ownerCallback.owner = owner;
    ownerCallback.onPress = std::move(onPress);
    ownerCallback.onRelease = std::move(onRelease);

    ownerCallbacks[keyCode].push_back(std::move(ownerCallback));
}

void BindManager::removeCallbackForOwner(void* owner, const int keyCode) {
    auto it = ownerCallbacks.find(keyCode);
    if (it == ownerCallbacks.end()) {
        return;
    }

    auto& callbacks = it->second;
    callbacks.erase(
        std::remove_if(callbacks.begin(), callbacks.end(),
            [owner](const OwnerCallback& cb) { return cb.owner == owner; }),
        callbacks.end()
    );

    if (callbacks.empty()) {
        ownerCallbacks.erase(it);
    }
}

BindManager& BindManager::getInstance() {
    static BindManager instance;
    return instance;
}
