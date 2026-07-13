#include "../../../../includes/module/impl/misc/FastPlaceModule.h"
#include "wrapper/minecraft/client/minecraft.h"
#include "handler/ModuleHandler.h"

void FastPlaceModule::onUpdate(JniScope& scope) {

    if (mode == 0) {
        Minecraft theMc = Minecraft::getMinecraft(scope.getEnv());
        if (!theMc.isNull()) {
            EntityClientPlayerMP thePlayer = theMc.thePlayer();
            if (!thePlayer.isNull()) {
                if (!onlyBlock || thePlayer.hasBlock()) {
                    if (theMc.rightClickDelayTimer() == 4) {
                        theMc.setRightClickDelayTimer(tickDelay);
                    }
                }
            }
        }
        Sleep(16);
        return;
    }

    if (holdToClick && (GetKeyState(VK_RBUTTON) & 0x8000) == 0) {
        Sleep(5);
        return;
    }

    if (onlyBlock) {
        Minecraft mc = Minecraft::getMinecraft(scope.getEnv());
        if (!mc.isNull()) {
            EntityClientPlayerMP p = mc.thePlayer();
            if (!p.isNull() && !p.hasBlock()) {
                Sleep(5);
                return;
            }
        }
    }

    HWND hWnd = GetForegroundWindow();
    if (!hWnd) { Sleep(5); return; }

    DWORD pId = 0;
    GetWindowThreadProcessId(hWnd, &pId);
    if (pId != currentPId) { Sleep(5); return; }

    const float meanTime    = 1000.0f / this->average;
    const float meanTimeDev = meanTime / 4.0f;
    int cycleDelay = static_cast<int>(boxMuller(meanTime, meanTimeDev));

    if (this->exhaust) {
        if (randomInt(0, 100) >= 95)
            cycleDelay = static_cast<int>(90.0f * (static_cast<float>(rand()) / RAND_MAX) + 90.0f);
        if (randomInt(0, 100) >= 99)
            cycleDelay = static_cast<int>(120.0f * (static_cast<float>(rand()) / RAND_MAX) + 120.0f);
    }

    const int holdDelay = randomInt(10, 20);

    PostMessageA(hWnd, WM_RBUTTONDOWN, 0, 0);
    Sleep(holdDelay);
    PostMessageA(hWnd, WM_RBUTTONUP, 0, 0);

    const ULONGLONG now = GetTickCount64();
    if ((now - lastClickTime) >= static_cast<ULONGLONG>(1500 + randomInt(0, 2500))) {
        if (randomInt(1, 100) <= randomInt(10, 18)) {
            Sleep(holdDelay);
            PostMessageA(hWnd, WM_RBUTTONDOWN, 0, 0);
            Sleep(holdDelay);
            PostMessageA(hWnd, WM_RBUTTONUP, 0, 0);
            cycleDelay -= 2 * holdDelay;
            lastClickTime = now;
        }
    }

    const int remaining = cycleDelay - holdDelay;
    if (remaining > 0) Sleep(remaining);
}

REGISTER_MODULE(FastPlaceModule, ModuleType::FAST_PLACE)
