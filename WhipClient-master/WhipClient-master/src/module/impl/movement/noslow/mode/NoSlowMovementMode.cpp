#include "module/impl/movement/noslow/mode/NoSlowMovementMode.h"

#include "wrapper/minecraft/client/minecraft.h"
#include "handler/ProviderHandler.h"
#include "provider/impl/GameStateProvider.h"
#include <Windows.h>

void NoSlowMovementMode::handlePacketSend(const AddSendQueueEvent& event, std::vector<bool> itemMode) {

}

void NoSlowMovementMode::handleEntityLivingUpdate(
    const EntityLivingUpdateEvent& event,
    std::vector<bool> itemMode,
    float powerMultiplier
) {

    auto& mutableEvent = const_cast<EntityLivingUpdateEvent&>(event);

    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState || !gameState->inGameHasFocus()) {
        return;
    }

    Minecraft mc = Minecraft::getMinecraft(event.getEnv());

    auto thePlayer = mc.thePlayer();
    if (thePlayer.isNull()) {
        return;
    }

    ItemStack heldItem = thePlayer.getHeldItem();
    GameSettings gameSettings = mc.gameSettings();

    if (heldItem.isNull()) {
        return;
    }

    bool useItemPressed = gameSettings.keyBindUseItem().pressed();

    bool shouldApply = false;

    if (itemMode[0] == true && heldItem.isSword() && useItemPressed) {
        shouldApply = true;
    }
    else if (itemMode[1] == true && heldItem.isPunch() && useItemPressed) {
        shouldApply = true;
    }
    else if (itemMode[2] == true && heldItem.isConsumable() && useItemPressed) {
        shouldApply = true;
    }
    else if (itemMode[3] == true && useItemPressed) {
        shouldApply = true;
    }

    if (shouldApply) {
        mutableEvent.setshouldApplySlow(true);
        const float noSlowFactor = 1.0f + (4.0f * powerMultiplier);

        const float originalForward = thePlayer.getMovementInput().getMoveForward();
        const float originalStrafe = thePlayer.getMovementInput().getMoveStrafe();

        const float newMoveForward = originalForward * noSlowFactor;
        const float newMoveStrafe = originalStrafe * noSlowFactor;

        mutableEvent.setMoveForward(newMoveForward);
        mutableEvent.setMoveStrafe(newMoveStrafe);
    }

}
