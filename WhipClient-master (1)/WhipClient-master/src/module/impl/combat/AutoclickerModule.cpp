#include "../../../../includes/module/impl/combat/AutoclickerModule.h"
#include "../../../../includes/module/impl/combat/autorefill/AutoRefillModule.h"
#include "../../../../includes/module/impl/combat/throw/ThrowModule.h"
#include <fstream>
#include <widgets.h>
#include <algorithm>
#include <functional>
#include "../../../../includes/handler/ModuleHandler.h"
#include "../../../../includes/handler/ProviderHandler.h"
#include "../../../../includes/provider/impl/GameStateProvider.h"
#include "wrapper/minecraft/client/minecraft.h"

void AutoClickerModule::resetPreciseState() {
    nextClickTick.QuadPart = 0;
    pendingUpTick.QuadPart = 0;
    buttonHeld = false;
}

void AutoClickerModule::flushPendingUp(HWND hWnd) {
    if (!buttonHeld) return;

    if (qpcFreq.QuadPart == 0) {
        buttonHeld = false;
        return;
    }

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    if (now.QuadPart >= pendingUpTick.QuadPart) {
        if (hWnd) PostMessageA(hWnd, 0x202, 0, 0);
        buttonHeld = false;
    }
}

void AutoClickerModule::handlePreciseBlatant(HWND hWnd, float cps) {
    if (!hWnd || cps <= 0.0f) return;
    if (qpcFreq.QuadPart == 0) QueryPerformanceFrequency(&qpcFreq);
    if (buttonHeld) return;

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);

    if (nextClickTick.QuadPart == 0) {
        nextClickTick = now;
    }

    if (now.QuadPart < nextClickTick.QuadPart) return;

    const LONGLONG periodTicks = static_cast<LONGLONG>(static_cast<double>(qpcFreq.QuadPart) / cps);
    const int holdMs = this->noHitDelay ? 1 : 3;
    const LONGLONG holdTicks = (qpcFreq.QuadPart * holdMs) / 1000;

    PostMessageA(hWnd, 0x201, 0, 0);
    buttonHeld = true;
    pendingUpTick.QuadPart = now.QuadPart + holdTicks;

    nextClickTick.QuadPart += periodTicks;
    if (nextClickTick.QuadPart <= now.QuadPart) {
        nextClickTick.QuadPart = now.QuadPart + periodTicks;
    }
}

void AutoClickerModule::onUpdate(JniScope& scope) {
    HWND hWnd = GetForegroundWindow();

    flushPendingUp(hWnd);

    if (!hWnd) {
        resetPreciseState();
        return;
    }

    DWORD pId = 0;
    GetWindowThreadProcessId(hWnd, &pId);

    if (pId != this->currentPId) {
        resetPreciseState();
        return;
    }

    if (this->holdToClick && (GetAsyncKeyState(VK_LBUTTON) & 0x8000) == 0) {
        resetPreciseState();
        return;
    }

    static bool clickEnfonce = false;
    if (ThrowModule::isThrowing()) {

        if (clickEnfonce) {
            PostMessageA(hWnd, 0x202, 0, 0);
            clickEnfonce = false;
        }
        resetPreciseState();
        return;
    }

    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState) {
        resetPreciseState();
        return;
    }

    Minecraft theMc = Minecraft::getMinecraft(scope.getEnv());
    if (theMc.isNull()) {
        resetPreciseState();
        return;
    }

    const WorldClient theWorld = theMc.theWorld();
    EntityClientPlayerMP thePlayer = theMc.thePlayer();
    MovingObjectPosition movingObjectPosition = theMc.objectMouseOver();

    if (theWorld.isNull() || thePlayer.isNull()) {
        resetPreciseState();
        return;
    }

    bool isLookingAtBlock = false;
    if (!movingObjectPosition.isNull()) {
        isLookingAtBlock = (movingObjectPosition.typeOfHit() == MovingObjectPosition::TypeOfHit::BLOCK);
    }

    const bool inGameCheck = gameState->inGameHasFocus()
            && (!this->weaponsOnly || gameState->hasWeaponInHand())
            && (!this->breakBlock || !isLookingAtBlock);

    const bool inInventoryCheck = !gameState->inGameHasFocus() && this->inventoryClick
        && (gameState->isInventoryOpen() || gameState->isChestOpen())
        && (!this->preventUnrefill || (gameState->isChestOpen() || !thePlayer.hasFullHotbar()));

    const bool shouldClick = (inGameCheck && !gameState->isInventoryOpen() && !gameState->isChestOpen())
                          || inInventoryCheck;

    if (!shouldClick || AutoRefillModule::isRefilling_()) {
        resetPreciseState();
        return;
    }

    if (this->breakBlock && isLookingAtBlock
        && !gameState->isInventoryOpen() && !gameState->isChestOpen()) {
        if (!clickEnfonce) {
            PostMessageA(hWnd, 0x201, 0, 0);
            clickEnfonce = true;
        }
        return;
    }
    else {
        clickEnfonce = false;
    }

    const bool blatantInv = inInventoryCheck && this->fastRefill;

    if (this->mode == 1 || blatantInv) {
        const float cps = blatantInv ? (this->fastRefill ? 30.0f : 25.0f)
                                     : (inInventoryCheck ? 25.0f : this->average);
        handlePreciseBlatant(hWnd, cps);
        return;
    }

    if (this->mode == 0 || this->mode == 2) {
        const float average = inInventoryCheck ? 25.0f : this->average;
        const float meanTime = 1000.0f / average;
        const float meanTimeDev = meanTime / 4.0f;

        int releaseDelay = static_cast<int>(boxMuller(meanTime, meanTimeDev));

        if (this->exhaust) {
            if (randomInt(0, 100) >= 95) releaseDelay = static_cast<int>(
                                             90.0f * (static_cast<float>(rand()) / static_cast<float>(RAND_MAX)) +
                                             90.0f);
            if (randomInt(0, 100) >= 99) releaseDelay = static_cast<int>(
                                             120.0f * (static_cast<float>(rand()) / static_cast<float>(RAND_MAX)) +
                                             120.0f);
        }

        PostMessageA(hWnd, 0x201, 0, 0);

        const int holdDelay = this->noHitDelay ? randomInt(1, 5) : randomInt(10, 20);
        Sleep(holdDelay);

        PostMessageA(hWnd, 0x202, 0, 0);

        releaseDelay -= holdDelay;
        releaseDelay -= static_cast<int>(average / 10.0f);
        if (releaseDelay > 0) Sleep(releaseDelay);
    }
}

REGISTER_MODULE(AutoClickerModule, ModuleType::AUTOCLICKER)
