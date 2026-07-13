#pragma once
#include "AutoRefillMode.h"

#include <atomic>
#include <vector>
#include <mutex>

class AutoRefillSemiBlatantMode final : public AutoRefillMode {
    static bool wasLeftClickPressed;

    static std::atomic<bool> active;

    struct PendingClick { int slot; int windowId; int delayMs; };
    static std::mutex batchMutex;
    static std::vector<PendingClick> batchQueue;
    static std::atomic<bool> batchReady;
    static std::atomic<bool> batchDone;
    static int currentSpeed;

public:
    static void onTick(JNIEnv* env);
    static void onPostLivingUpdate(JNIEnv* env);
    static void flushBatch();

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

    bool isInstant() const override { return false; }

    int dynamicDistanceSpeed(int baseSpeed, int distance, bool active) override {
        return baseSpeed;
    }

    void onEnable() override;
    void onDisable() override;
};
