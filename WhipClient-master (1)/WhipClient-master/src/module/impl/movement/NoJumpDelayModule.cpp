#include "../../../../includes/module/impl/movement/NoJumpDelayModule.h"
#include "wrapper/minecraft/client/minecraft.h"
#include "handler/ModuleHandler.h"

NoJumpDelayModule::NoJumpDelayModule() = default;

void NoJumpDelayModule::onUpdate(JniScope& scope) {
    Minecraft theMc = Minecraft::getMinecraft(scope.getEnv());
    if (theMc.isNull()) {
        return;
    }

    const EntityClientPlayerMP player = theMc.thePlayer();
    if (player.isNull()) {
        return;
    }

    player.JumpTicks(0);
}

REGISTER_MODULE(NoJumpDelayModule, ModuleType::NO_JUMP_DELAY)
