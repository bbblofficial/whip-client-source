#include "module/impl/movement/BridgeAssistModule.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/client/settings/GameSettings.h"
#include "wrapper/minecraft/entity/player/EntityPlayer.h"
#include "wrapper/minecraft/entity/player/inventoryplayer.h"
#include "wrapper/minecraft/item/ItemStack.h"
#include "wrapper/minecraft/item/Item.h"
#include "wrapper/minecraft/util/Vec3.h"
#include "wrapper/minecraft/util/MovingObjectPosition.h"
#include "wrapper/minecraft/world/World.h"
#include "setting/SettingMacros.h"
#include "util/Debug.h"
#include <windows.h>
#include <cmath>

BridgeAssistModule::BridgeAssistModule() : SharedThreadBaseModule(BindType::TOGGLE, 0) {}

void BridgeAssistModule::onLoad() {
    SharedThreadBaseModule::onLoad();

    COMBO_SETTING(mode, "Legit", "Blatant");
    BOOL_SETTING_CONDITIONAL(disableSprinting, false);
}

void BridgeAssistModule::onEnable() {
    SharedThreadBaseModule::onEnable();
    hasPressedShift_ = false;
    isBridging_ = false;
    isEdge_ = false;
    m_prev = false;
    jumped_ = false;
    wasForwardPressed_ = false;
}

void BridgeAssistModule::onDisable() {
    SharedThreadBaseModule::onDisable();
    if (isEdge_ || m_prev) {
        if (JniScope scope(true); scope.isValid()) {
            JNIEnv* env = scope.getEnv();
            auto mc = Minecraft::getMinecraft(env);
            if (!mc.isNull()) {
                auto gs = mc.gameSettings();
                if (!gs.isNull()) {
                    KeyBinding sneakBind = gs.keyBindSneak();
                    if (!sneakBind.isNull()) {
                        unsneak(sneakBind);
                    }
                }
            }
        }
        isEdge_ = false;
        m_prev = false;
    }
    if (wasForwardPressed_) {
        sendKey('W', false);
        wasForwardPressed_ = false;
    }
}

void BridgeAssistModule::onUpdate(JniScope& scope) {
    JNIEnv* env = scope.getEnv();

    auto mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) { m_prev = false; isEdge_ = false; return; }

    auto player = mc.thePlayer();
    if (player.isNull()) { m_prev = false; isEdge_ = false; return; }

    auto gameSettings = mc.gameSettings();
    if (gameSettings.isNull()) { m_prev = false; isEdge_ = false; return; }

    KeyBinding sneakBind = gameSettings.keyBindSneak();
    if (sneakBind.isNull()) { m_prev = false; isEdge_ = false; return; }

    bool isSneaking = sneakBind.isPhysDown();

    if (mode == 1) {
        if ((GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0 && player.rotationPitch() >= 70.0f) {
            if (mc.inGameHasFocus() && mc.rightClickDelayTimer() == 4) {
                mc.setRightClickDelayTimer(0);
            }
        }
    }

    auto currentScreen = mc.currentScreen();
    if (!currentScreen.isNull()) {
        unsneak(sneakBind);
        isBridging_ = false;
        return;
    }

    if (disableSprinting && player.isSprinting()) {
        unsneak(sneakBind);
        isBridging_ = false;
        return;
    }

    if (player.rotationPitch() < 70.0f) {
        unsneak(sneakBind);
        isBridging_ = false;
        return;
    }

    double playerX = player.posX();
    double playerY = player.posY();
    double playerZ = player.posZ();

    auto world = mc.theWorld();
    if (world.isNull()) {
        unsneak(sneakBind);
        return;
    }

    auto from = Vec3MC::createVec3(env, playerX, playerY + 1.0, playerZ);
    auto to = Vec3MC::createVec3(env, playerX, -1000000.0, playerZ);

    if (from.isNull() || to.isNull()) {
        unsneak(sneakBind);
        return;
    }

    auto mop = world.rayTraceBlocks(from, to);
    bool res = !mop.isNull();

    double hitY = 0.0;
    if (res) {
        Vec3MC hitVec = mop.hitVec();
        if (!hitVec.isNull()) {
            hitY = hitVec.getY();
        } else {
            res = false;
        }
    }

    double diffY = playerY - hitY;
    diffY -= 1.0;

    if (GetAsyncKeyState(VK_SPACE) & 0x0001) {
        jumped_ = true;
    }

    if (jumped_) {
        unsneak(sneakBind);
        if (player.motionY() < 0.0 || diffY <= 0.0) {
            jumped_ = false;
        }
        isBridging_ = false;
        return;
    }

    if (diffY != 0 && diffY <= 0.0) {
        unsneak(sneakBind);
        isBridging_ = false;
        return;
    }

    m_prev = isEdge_;
    isEdge_ = false;

    bool isFalling = std::abs(player.motionY()) > 0.5;

    if (!isFalling) {
        isBridging_ = true;
        if (static_cast<int>(diffY) != 0 || !res) {
            sneak(sneakBind);
        } else {
            unsneak(sneakBind);
        }
    } else {
        unsneak(sneakBind);
    }
}

void BridgeAssistModule::sneak(KeyBinding& sneakBind) {
    isEdge_ = true;
    if (!m_prev) {
        sneakBind.pressed(true);
        m_prev = true;
    }
}

void BridgeAssistModule::unsneak(KeyBinding& sneakBind) {
    isEdge_ = false;
    if (m_prev) {
        sneakBind.pressed(false);
        m_prev = false;
    }
}

void BridgeAssistModule::sendKey(WORD vkKey, bool down) {
    INPUT ip;
    ip.type = INPUT_KEYBOARD;
    ip.ki.wScan = 0;
    ip.ki.time = 0;
    ip.ki.dwExtraInfo = 0;
    ip.ki.wVk = vkKey;
    ip.ki.dwFlags = down ? 0 : KEYEVENTF_KEYUP;
    SendInput(1, &ip, sizeof(INPUT));
}

REGISTER_MODULE(BridgeAssistModule, ModuleType::BRIDGE_ASSIST)
