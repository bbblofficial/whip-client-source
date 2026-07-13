#include "../../../../../../includes/module/impl/combat/autorefill/mode/AutoRefillLegitMode.h"
#include <windows.h>
#include "util/ClientStrings.h"
#include "hook/sub/GetSlotAtPositionHook.h"
#include "wrapper/minecraft/client/gui/GuiScreen.h"
#include "wrapper/minecraft/client/gui/inventory/GuiContainer.h"
#include "wrapper/minecraft/inventory/Slot.h"
#include "wrapper/java/util/ArrayList.h"

bool AutoRefillLegitMode::wasLeftClickPressed = false;
std::random_device AutoRefillLegitMode::rd;
std::mt19937 AutoRefillLegitMode::gen(rd());

std::mutex AutoRefillLegitMode::tickMutex;
std::condition_variable AutoRefillLegitMode::tickCv;
std::atomic<uint64_t> AutoRefillLegitMode::tickCount{0};
std::atomic<bool> AutoRefillLegitMode::active{false};

void AutoRefillLegitMode::notifyTick() {
    {
        std::lock_guard lock(tickMutex);
        tickCount.fetch_add(1, std::memory_order_release);
    }
    tickCv.notify_all();
}

void AutoRefillLegitMode::waitTicks(int n) {
    if (n <= 0) return;
    std::unique_lock lock(tickMutex);
    const uint64_t target = tickCount.load(std::memory_order_acquire) + n;
    tickCv.wait_for(lock, std::chrono::milliseconds(n * 100), [&] {
        return tickCount.load(std::memory_order_acquire) >= target || !active.load(std::memory_order_acquire);
    });
}

void AutoRefillLegitMode::waitForNextTick() {
    waitTicks(1);
}

int AutoRefillLegitMode::msToTicks(int ms) {
    if (ms <= 0) return 0;
    int ticks = (ms + 49) / 50;
    return std::max(1, ticks);
}

AutoRefillLegitMode::AutoRefillLegitMode() = default;

void AutoRefillLegitMode::onEnable() {
    wasLeftClickPressed = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    active.store(true, std::memory_order_release);
    waitForNextTick();
    keybd_event(VK_SHIFT, 0, 0, 0);
}

void AutoRefillLegitMode::onDisable() {
    {
        std::lock_guard lock(GetSlotAtPositionHook::slotsMutex);
        while (!GetSlotAtPositionHook::spoofedSlots.empty()) {
            GetSlotAtPositionHook::spoofedSlots.pop();
        }
        GetSlotAtPositionHook::spoofActive = false;
    }

    waitForNextTick();

    if (wasLeftClickPressed) {
        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
    }

    keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);

    active.store(false, std::memory_order_release);
    tickCv.notify_all();

    wasLeftClickPressed = false;
}

void AutoRefillLegitMode::performClick(int slot,
    int speed,
    int distance,
    Container& container,
    EntityClientPlayerMP& player,
    Minecraft& mc,
    const bool dynamicSpeed,
    const bool transition
    ) {

    if (speed > 0) {
        if (transition) {
            const int adjustedSpeed = static_cast<int>(AutoRefillLegitMode::dynamicSpeed(dynamicSpeed, speed));
            const int tickDelay = msToTicks(adjustedSpeed * 10);
            waitTicks(tickDelay);
        } else {
            const int tickDelay = msToTicks(speed * 10);
            waitTicks(tickDelay);
        }
    }

    if (!active.load(std::memory_order_acquire)) return;

    {
        std::lock_guard<std::mutex> lock(GetSlotAtPositionHook::slotsMutex);
        GetSlotAtPositionHook::spoofedSlots.push(slot);
        GetSlotAtPositionHook::spoofActive = true;
    }

    const ScaledResolutionData scaledRes = getScaledResolution(mc);
    int guiLeft = (scaledRes.scaledWidth  - 176) / 2;
    int guiTop  = (scaledRes.scaledHeight - 166) / 2;
    {
        GuiScreen screen = mc.currentScreen();
        if (!screen.isNull()) {
            screen.setDeleteRef(false);
            GuiContainer guiC(screen.getEnv(), screen.getObj());
            const int gl = guiC.guiLeft();
            const int gt = guiC.guiTop();

            if (gl >= 0 && gt >= 0 &&
                gl < scaledRes.scaledWidth && gt < scaledRes.scaledHeight) {
                guiLeft = gl;
                guiTop  = gt;
            }
        }
    }

    int slotXOff = 0;
    int slotYOff = 0;
    {
        ArrayList slots = container.inventorySlots();
        if (!slots.isNull() && slot >= 0 && slot < slots.size()) {
            JavaObject slotJO = slots.get(slot);
            if (!slotJO.isNull()) {
                slotJO.setDeleteRef(false);
                Slot s(mc.getEnv(), slotJO.getObj());
                s.setDeleteRef(false);
                slotXOff = s.xDisplayPosition();
                slotYOff = s.yDisplayPosition();
            }
        }
    }
    const int slotX = guiLeft + slotXOff + 8;
    const int slotY = guiTop  + slotYOff + 8;

    const double scaleX = static_cast<double>(mc.displayWidth())  / static_cast<double>(scaledRes.scaledWidth);
    const double scaleY = static_cast<double>(mc.displayHeight()) / static_cast<double>(scaledRes.scaledHeight);
    int realX = static_cast<int>(static_cast<double>(slotX) * scaleX);
    int realY = static_cast<int>(static_cast<double>(slotY) * scaleY);

    if (!mc.isFullScreen()) {
        HWND minecraftWindow = FindWindowA(Strings::lwjglWindow(), nullptr);
        if (!minecraftWindow) {
            minecraftWindow = FindWindowA(Strings::glfwWindow(), nullptr);
        }

        if (!minecraftWindow) {
            struct EnumData { DWORD pid; HWND hwnd; LONG area; } data{GetCurrentProcessId(), nullptr, 0};
            EnumWindows([](HWND h, LPARAM lp) -> BOOL {
                auto* d = reinterpret_cast<EnumData*>(lp);
                DWORD pid = 0;
                GetWindowThreadProcessId(h, &pid);
                if (pid != d->pid) return TRUE;
                if (!IsWindowVisible(h)) return TRUE;
                if (GetWindow(h, GW_OWNER) != nullptr) return TRUE;
                RECT cr{};
                if (!GetClientRect(h, &cr)) return TRUE;
                LONG w = cr.right - cr.left;
                LONG hgt = cr.bottom - cr.top;
                if (w < 100 || hgt < 100) return TRUE;
                LONG area = w * hgt;
                if (area > d->area) {
                    d->area = area;
                    d->hwnd = h;
                }
                return TRUE;
            }, reinterpret_cast<LPARAM>(&data));
            minecraftWindow = data.hwnd;
        }
        if (minecraftWindow) {

            POINT clientOrigin{0, 0};
            ClientToScreen(minecraftWindow, &clientOrigin);
            realX += clientOrigin.x;
            realY += clientOrigin.y;
        }
    }

    if (speed >= 3) {
        addMouseHumanization(realX, realY);
    }

    if (transition) {

        const int baseMouseSpeed = 15 + (10 - speed) * 185 / 10;
        const int adjustedSpeed = AutoRefillLegitMode::dynamicSpeed(dynamicSpeed, baseMouseSpeed);
        smoothMouseMove(realX, realY, static_cast<int>(adjustedSpeed));
    } else {
        SetCursorPos(realX, realY);
    }

    if (speed >= 2) {
        waitForNextTick();
    } else {
        Sleep(20);
    }
    if (!active.load(std::memory_order_acquire)) return;
    int clickCount;
    if (speed == 0) {
        clickCount = 9;
    } else {
        clickCount = std::clamp(3 - speed, 1, 3);
    }
    for (int i = 0; i < clickCount; i++) {
        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
        mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
    }
}

int AutoRefillLegitMode::getSlotXPosition(int slot) {
    const int inventorySlot = slot - 9;
    const int col = inventorySlot % 9;
    return col * 18;
}

int AutoRefillLegitMode::getSlotYPosition(int slot) {
    const int inventorySlot = slot - 9;
    const int row = inventorySlot / 9;
    return row * 18;
}

int AutoRefillLegitMode::dynamicDistanceSpeed(const int baseSpeed, const int distance, bool active) {
    if (!active) {
        return std::max(5, baseSpeed);
    }

    if (baseSpeed < 4) {
        return std::max(5, baseSpeed);
    }

    if (distance <= 4) {
        return std::max(5, baseSpeed - 2);
    }

    if (distance <= 6) {
        return std::max(5, baseSpeed - 5);
    }

    return std::max(5, baseSpeed - 8);
}

ScaledResolutionData AutoRefillLegitMode::getScaledResolution(Minecraft& mc) {
    const int displayWidth = mc.displayWidth();
    const int displayHeight = mc.displayHeight();
    const bool isUnicode = mc.isUnicode();
    GameSettings gameSettings = mc.gameSettings();
    const int guiScale = gameSettings.guiScale();
    return calculateScaledResolution(displayWidth, displayHeight, guiScale, isUnicode);
}

ScaledResolutionData AutoRefillLegitMode::calculateScaledResolution(int displayWidth, int displayHeight, int guiScale, bool isUnicode) {
    ScaledResolutionData data;
    data.scaledWidth = displayWidth;
    data.scaledHeight = displayHeight;
    data.scaleFactor = 1;
    int i = guiScale;
    if (i == 0) {
        i = 1000;
    }
    while (data.scaleFactor < i &&
        data.scaledWidth / (data.scaleFactor + 1) >= 320 &&
        data.scaledHeight / (data.scaleFactor + 1) >= 240) {
        ++data.scaleFactor;
    }

    if (isUnicode && data.scaleFactor % 2 != 0 && data.scaleFactor != 1) {
        --data.scaleFactor;
    }
    data.scaledWidthD = static_cast<double>(data.scaledWidth) / static_cast<double>(data.scaleFactor);
    data.scaledHeightD = static_cast<double>(data.scaledHeight) / static_cast<double>(data.scaleFactor);
    data.scaledWidth = ceiling_double_int(data.scaledWidthD);
    data.scaledHeight = ceiling_double_int(data.scaledHeightD);
    return data;
}

int AutoRefillLegitMode::ceiling_double_int(const double value) {
    const int i = static_cast<int>(value);
    return value > static_cast<double>(i) ? i + 1 : i;
}

void AutoRefillLegitMode::smoothMouseMove(int targetX, int targetY, int speed) {
    POINT currentPos;
    GetCursorPos(&currentPos);

    const int startX = currentPos.x;
    const int startY = currentPos.y;

    const int deltaX = targetX - startX;
    const int deltaY = targetY - startY;

    const double distance = sqrt(deltaX * deltaX + deltaY * deltaY);

    if (distance < 5 || speed >= 45) {
        SetCursorPos(targetX, targetY);
        return;
    }

    int steps = static_cast<int>(distance / speed);
    const int minSteps = (speed >= 30) ? 2 : 3;
    steps = std::max(minSteps, std::min(steps, 12));

    for (int i = 1; i <= steps; i++) {
        const float t = static_cast<float>(i) / static_cast<float>(steps);

        const float easeT = t * t * (3.0f - 2.0f * t);

        int currentX = startX + static_cast<int>(deltaX * easeT);
        int currentY = startY + static_cast<int>(deltaY * easeT);

        if (i < steps) {
            std::uniform_int_distribution jitterDist(-2, 2);
            currentX += jitterDist(gen);
            currentY += jitterDist(gen);
        }

        SetCursorPos(currentX, currentY);
        const int sleepTime = 2 + (i % 2);
        Sleep(sleepTime);
    }

    SetCursorPos(targetX, targetY);
}

void AutoRefillLegitMode::addMouseHumanization(int& x, int& y) {
    std::uniform_int_distribution offsetDist(-6, 6);
    x += offsetDist(gen);
    y += offsetDist(gen);
}
