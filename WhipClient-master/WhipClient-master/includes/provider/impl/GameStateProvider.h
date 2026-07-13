#pragma once

#include "../base/BaseProvider.h"
#include "../../bus/EventBus.h"
#include "../../event/sub/UpdateEvent.h"
#include <atomic>
#include <cstdint>

enum class ScreenState : uint8_t {
    NONE = 0,
    INVENTORY = 1 << 0,
    CHEST = 1 << 1,
    CHAT = 1 << 2,
    OPTIONS = 1 << 3
};

struct alignas(64) GameStateCache {
    std::atomic<bool> inGameHasFocus{false};
    std::atomic<uint8_t> screenFlags{0};
    std::atomic<bool> hasScreen{false};
    std::atomic<bool> hasWeapon{false};

    bool isScreenOpen(ScreenState state) const {
        return (screenFlags.load(std::memory_order_acquire) & static_cast<uint8_t>(state)) != 0;
    }

    void setScreenFlag(ScreenState state, bool value) {
        uint8_t current = screenFlags.load(std::memory_order_acquire);
        uint8_t newFlags;
        if (value) {
            newFlags = current | static_cast<uint8_t>(state);
        } else {
            newFlags = current & ~static_cast<uint8_t>(state);
        }
        screenFlags.store(newFlags, std::memory_order_release);
    }

    void clearScreenFlags() {
        screenFlags.store(0, std::memory_order_release);
        hasScreen.store(false, std::memory_order_release);
    }
};

class GameStateProvider final : public BaseProvider<GameStateProvider, ProviderType::GAME_STATE> {
    GameStateCache cache;

public:
    GameStateProvider() = default;
    ~GameStateProvider() override = default;

    void onEnable() override;
    void onDisable() override;

    bool inGameHasFocus() const {
        return cache.inGameHasFocus.load(std::memory_order_acquire);
    }

    bool hasAnyScreen() const {
        return cache.hasScreen.load(std::memory_order_acquire);
    }

    bool isInventoryOpen() const {
        return cache.isScreenOpen(ScreenState::INVENTORY);
    }

    bool isChestOpen() const {
        return cache.isScreenOpen(ScreenState::CHEST);
    }

    bool isChatOpen() const {
        return cache.isScreenOpen(ScreenState::CHAT);
    }

    bool isOptionsOpen() const {
        return cache.isScreenOpen(ScreenState::OPTIONS);
    }

    bool isInGame() const {
        return inGameHasFocus() && !hasAnyScreen();
    }

    bool canReceiveInput() const {
        return inGameHasFocus() || isInventoryOpen() || isChestOpen();
    }

    bool hasWeaponInHand() const {
        return cache.hasWeapon.load(std::memory_order_acquire);
    }

private:
    void onUpdate(const UpdateEvent& event);
};
