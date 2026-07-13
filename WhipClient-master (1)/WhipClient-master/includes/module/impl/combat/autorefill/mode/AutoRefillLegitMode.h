#pragma once

#include <random>
#include <mutex>
#include <condition_variable>
#include <atomic>

#include "AutoRefillMode.h"
#include "../../../../../util/MathUtils.h"

struct ScaledResolutionData {
    double scaledWidthD;
    double scaledHeightD;
    int scaledWidth;
    int scaledHeight;
    int scaleFactor;
};

class AutoRefillLegitMode final : public AutoRefillMode {
    static bool wasLeftClickPressed;
    static std::random_device rd;
    static std::mt19937 gen;

    static std::mutex tickMutex;
    static std::condition_variable tickCv;
    static std::atomic<uint64_t> tickCount;
    static std::atomic<bool> active;

public:
    AutoRefillLegitMode();

    ~AutoRefillLegitMode() override = default;

    static void notifyTick();
    static void waitTicks(int n);
    static void waitForNextTick();
    static int msToTicks(int ms);

    void performClick(
        int slot,
        int speed,
        int distance,
        Container& container,
        EntityClientPlayerMP& player,
        Minecraft& mc,
        bool dynamicSpeed,
        bool transition
    ) override;

    bool isInstant() const override {
        return false;
    }

    static double dynamicSpeed(const bool active, const double baseSpeed) {
        if (!active) return baseSpeed;
        const double adjusted = baseSpeed + randomDouble(-3, 5);
        return std::max(0.0, adjusted);
    }

    int dynamicDistanceSpeed(int baseSpeed, int distance, bool active) override;

    int getSlotXPosition(int slot);

    int getSlotYPosition(int slot);

    ScaledResolutionData getScaledResolution(Minecraft& mc);

    ScaledResolutionData calculateScaledResolution(int displayWidth, int displayHeight, int guiScale, bool isUnicode);

    int ceiling_double_int(double value);

    void smoothMouseMove(int targetX, int targetY, int speed = 5);

    void addMouseHumanization(int& x, int& y);

    void onEnable() override;

    void onDisable() override;
};
