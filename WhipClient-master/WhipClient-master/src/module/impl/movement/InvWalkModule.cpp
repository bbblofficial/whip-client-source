#include "../../../../includes/module/impl/movement/InvWalkModule.h"
#include "wrapper/minecraft/client/minecraft.h"
#include "handler/ModuleHandler.h"

InvWalkModule::InvWalkModule() = default;

void InvWalkModule::onLoad() {
    ListenedBaseModule::onLoad();

    COMBO_SETTING(mode, "Legit", "Blatant");
}

void InvWalkModule::onTick(const OnRunTickEvent& event) {
    if (!this->enable) return;
    JNIEnv* env = event.getEnv();
    if (!env) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    GuiScreen screen = mc.currentScreen();
    if (screen.isNull()) return;
    screen.setDeleteRef(false);

    if (screen.isChat()) return;

    GameSettings settings = mc.gameSettings();
    if (settings.isNull()) return;

    KeyBinding forward  = settings.keyBindForward();
    KeyBinding back     = settings.keyBindBack();
    KeyBinding left     = settings.keyBindLeft();
    KeyBinding right    = settings.keyBindRight();
    KeyBinding jump     = settings.keyBindJump();
    KeyBinding sneak    = settings.keyBindSneak();
    KeyBinding sprint   = settings.keyBindSprint();

    if (!forward.isNull()) forward.pressed(forward.isPhysDown());
    if (!back.isNull())    back.pressed(back.isPhysDown());
    if (!left.isNull())    left.pressed(left.isPhysDown());
    if (!right.isNull())   right.pressed(right.isPhysDown());
    if (!jump.isNull())    jump.pressed(jump.isPhysDown());
    if (!sneak.isNull())   sneak.pressed(false);

    const bool blatant    = (mode == 1);
    const bool wantSprint = blatant;

    if (!sprint.isNull()) sprint.pressed(wantSprint);

    EntityClientPlayerMP thePlayer = mc.thePlayer();
    if (!thePlayer.isNull()) {
        thePlayer.setSprinting(wantSprint);
    }
}

REGISTER_MODULE(InvWalkModule, ModuleType::INV_WALK)
