#include "../../../../includes/module/impl/movement/Sprint.h"
#include "wrapper/minecraft/client/minecraft.h"
#include "handler/ModuleHandler.h"

SprintModule::SprintModule() = default;

void SprintModule::onUpdate(JniScope& scope) {
    Minecraft theMc = Minecraft::getMinecraft(scope.getEnv());
    if (theMc.isNull()) {
        return;
    }

    GuiScreen screen = theMc.currentScreen();
    if (!screen.isNull()) {
        screen.setDeleteRef(false);
        return;
    }

    GameSettings gameSettings = theMc.gameSettings();
    if (gameSettings.isNull()) {
        return;
    }

    gameSettings.keyBindSprint().pressed(true);
}

REGISTER_MODULE(SprintModule, ModuleType::SPRINT)
