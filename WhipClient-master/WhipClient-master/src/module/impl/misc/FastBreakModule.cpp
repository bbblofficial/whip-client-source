#include "../../../../includes/module/impl/misc/FastBreakModule.h"
#include "wrapper/minecraft/client/minecraft.h"
#include "handler/ModuleHandler.h"
#include "handler/ProviderHandler.h"
#include "provider/impl/GameStateProvider.h"

FastBreakModule::FastBreakModule() = default;

void FastBreakModule::onUpdate(JniScope& scope) {
    if ((GetAsyncKeyState(VK_LBUTTON) & 0x8000) == 0) {
        return;
    }

    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState || !gameState->inGameHasFocus()) return;

    Minecraft theMc = Minecraft::getMinecraft(scope.getEnv());
    if (theMc.isNull()) return;

    WorldClient theWorld = theMc.theWorld();
    EntityClientPlayerMP thePlayer = theMc.thePlayer();
    PlayerControllerMP playerController = theMc.playerController();

    if (theWorld.isNull()
        || thePlayer.isNull()
        || playerController.isNull()
        ) {
        return;
    }

    if (mode == 0) {
        if (playerController.curBlockDamageMP() >= (1.0f - (power / 100.0f)))
            playerController.curBlockDamageMP(1.0f);
    }
    else if (mode == 1) {
        float curBlockDamageMP = playerController.curBlockDamageMP();
        if (curBlockDamageMP > 0.0f) {
            float damageDiff = curBlockDamageMP - this->lastBlockDamageMP;
            curBlockDamageMP += damageDiff * (multiplier - 1.0f);
            playerController.curBlockDamageMP(curBlockDamageMP);
            this->lastBlockDamageMP = curBlockDamageMP;
        }
        else if (this->lastBlockDamageMP > 0.0f) {
            this->lastBlockDamageMP = 0.0f;
        }
    }
}

REGISTER_MODULE(FastBreakModule, ModuleType::FAST_BREAK)
