#include "../../../../../../includes/module/impl/combat/autorefill/mode/AutoRefillSemiBlatantMode.h"
#include "util/MinecraftDetails.h"
#include "util/Debug.h"
#include <windows.h>
#include <timeapi.h>
#pragma comment(lib, "winmm.lib")

bool AutoRefillSemiBlatantMode::wasLeftClickPressed = false;
std::atomic<bool> AutoRefillSemiBlatantMode::active{false};

std::mutex AutoRefillSemiBlatantMode::batchMutex;
std::vector<AutoRefillSemiBlatantMode::PendingClick> AutoRefillSemiBlatantMode::batchQueue;
std::atomic<bool> AutoRefillSemiBlatantMode::batchReady{false};
std::atomic<bool> AutoRefillSemiBlatantMode::batchDone{false};
int AutoRefillSemiBlatantMode::currentSpeed = 5;

void AutoRefillSemiBlatantMode::onTick(JNIEnv* env) {
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) return;
    if (!batchReady.load(std::memory_order_acquire)) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) { batchDone.store(true, std::memory_order_release); return; }

    EntityClientPlayerMP player = mc.thePlayer();
    if (player.isNull()) { batchDone.store(true, std::memory_order_release); return; }

    {
        std::lock_guard lock(batchMutex);
        if (currentSpeed <= 0) {

            for (auto& click : batchQueue) {
                ItemStack res = mc.playerController().windowClick(click.windowId, click.slot, 0, 1, player);
                DEBUG_LOG("[AutoRefill][onTick] windowClick windowId=%d slot=%d mode=shift -> result %s",
                          click.windowId, click.slot, res.isNull() ? "NULL (nothing moved)" : "non-null (item moved)");
            }
            batchQueue.clear();
        } else {

            if (!batchQueue.empty()) {
                ItemStack res = mc.playerController().windowClick(batchQueue[0].windowId, batchQueue[0].slot, 0, 1, player);
                DEBUG_LOG("[AutoRefill][onTick] windowClick windowId=%d slot=%d mode=shift -> result %s",
                          batchQueue[0].windowId, batchQueue[0].slot, res.isNull() ? "NULL (nothing moved)" : "non-null (item moved)");
                batchQueue.erase(batchQueue.begin());
            }
        }
    }

    batchReady.store(false, std::memory_order_release);
    batchDone.store(true, std::memory_order_release);
}

void AutoRefillSemiBlatantMode::onPostLivingUpdate(JNIEnv* env) {
    if (MinecraftSession::getInstance().version != MinecraftVersion::V1_7_10) return;
    if (!batchReady.load(std::memory_order_acquire)) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) { batchDone.store(true, std::memory_order_release); return; }

    EntityClientPlayerMP player = mc.thePlayer();
    if (player.isNull()) { batchDone.store(true, std::memory_order_release); return; }

    {
        std::lock_guard lock(batchMutex);
        if (currentSpeed <= 0) {
            for (auto& click : batchQueue) {
                ItemStack res = mc.playerController().windowClick(click.windowId, click.slot, 0, 1, player);
                DEBUG_LOG("[AutoRefill][onPostLivingUpdate] windowClick windowId=%d slot=%d mode=shift -> result %s",
                          click.windowId, click.slot, res.isNull() ? "NULL (nothing moved)" : "non-null (item moved)");
            }
            batchQueue.clear();
        } else {
            if (!batchQueue.empty()) {
                ItemStack res = mc.playerController().windowClick(batchQueue[0].windowId, batchQueue[0].slot, 0, 1, player);
                DEBUG_LOG("[AutoRefill][onPostLivingUpdate] windowClick windowId=%d slot=%d mode=shift -> result %s",
                          batchQueue[0].windowId, batchQueue[0].slot, res.isNull() ? "NULL (nothing moved)" : "non-null (item moved)");
                batchQueue.erase(batchQueue.begin());
            }
        }
    }

    batchReady.store(false, std::memory_order_release);
    batchDone.store(true, std::memory_order_release);
}

void AutoRefillSemiBlatantMode::onEnable() {
    wasLeftClickPressed = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    active.store(true, std::memory_order_release);
    timeBeginPeriod(1);
}

void AutoRefillSemiBlatantMode::onDisable() {
    active.store(false, std::memory_order_release);
    timeEndPeriod(1);

    batchReady.store(false, std::memory_order_release);
    batchDone.store(true, std::memory_order_release);
    {
        std::lock_guard lock(batchMutex);
        batchQueue.clear();
    }

    if (wasLeftClickPressed)
        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
    wasLeftClickPressed = false;
}

void AutoRefillSemiBlatantMode::flushBatch() {
    {
        std::lock_guard lock(batchMutex);
        if (batchQueue.empty()) return;
        DEBUG_LOG("[AutoRefill][flushBatch] start: queueSize=%zu currentSpeed=%d (waiting on onTick/onPostLivingUpdate to drain)",
                  batchQueue.size(), currentSpeed);
    }

    if (currentSpeed <= 0) {

        batchDone.store(false, std::memory_order_release);
        batchReady.store(true, std::memory_order_release);
        int spins = 0;
        while (!batchDone.load(std::memory_order_acquire) && active.load(std::memory_order_acquire)) {
            Sleep(1);
            if (++spins == 1000)
                DEBUG_LOG("[AutoRefill][flushBatch] STILL SPINNING after ~1000ms: batchDone never set "
                          "-> the tick event is NOT firing while inventory open (Feather?). refilling_ stays true.");
        }
        DEBUG_LOG("[AutoRefill][flushBatch] done (instant), spins=%d active=%d", spins, active.load() ? 1 : 0);
    } else {

        int delayMs = currentSpeed * 50;

        while (active.load(std::memory_order_acquire)) {
            {
                std::lock_guard lock(batchMutex);
                if (batchQueue.empty()) break;
            }

            batchDone.store(false, std::memory_order_release);
            batchReady.store(true, std::memory_order_release);

            int spins = 0;
            while (!batchDone.load(std::memory_order_acquire) && active.load(std::memory_order_acquire)) {
                Sleep(1);
                if (++spins == 1000)
                    DEBUG_LOG("[AutoRefill][flushBatch] STILL SPINNING after ~1000ms: batchDone never set "
                              "-> the tick event is NOT firing while inventory open (Feather?). refilling_ stays true.");
            }

            Sleep(delayMs);
        }
        DEBUG_LOG("[AutoRefill][flushBatch] done (paced), active=%d", active.load() ? 1 : 0);
    }
}

void AutoRefillSemiBlatantMode::performClick(
    int slot,
    int speed,
    int distance,
    Container& container,
    EntityClientPlayerMP& player,
    Minecraft& mc,
    bool dynamicSpeed,
    bool transition)
{
    currentSpeed = speed;
    std::lock_guard lock(batchMutex);
    batchQueue.push_back({slot, container.windowId(), speed * 50});
}
