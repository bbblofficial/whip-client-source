#include "../../../../includes/module/impl/misc/TickLockerModule.h"

#include "handler/ProviderHandler.h"
#include "provider/impl/GameStateProvider.h"
#include "util/RenderUtils.h"
#include "wrapper/minecraft/client/minecraft.h"

TickLockerModule::~TickLockerModule() {
    if (isRightClickHeld) {
        releaseRightClick();
    }
}

void TickLockerModule::registerEvents() {
    subscribe<MouseBlockClickEvent>([this](const MouseBlockClickEvent& eventt) {
        onMouseLeftClick(eventt);
    }, EventPriority::HIGH, false);

    subscribe<Render3dEvent>([this](const Render3dEvent& event) {
            onRender3d(event);
    }, EventPriority::HIGH, false);
}

void TickLockerModule::holdRightClick() {
    if (!isRightClickHeld) {
        isRightClickHeld = true;

        INPUT input = {};
        input.type = INPUT_MOUSE;
        input.mi.dwFlags = MOUSEEVENTF_RIGHTDOWN;

        if (SendInput(1, &input, sizeof(INPUT)) != 1) {
            isRightClickHeld = false;
        }
    }
}

void TickLockerModule::releaseRightClick() {
    if (isRightClickHeld) {
        isRightClickHeld = false;

        INPUT input = {};
        input.type = INPUT_MOUSE;
        input.mi.dwFlags = MOUSEEVENTF_RIGHTUP;

        if (SendInput(1, &input, sizeof(INPUT)) != 1) {
            isRightClickHeld = true;
        } else {
            if (isBlocking) {
                cancelLeftClick = false;
                isBlocking = false;
            }
        }
    }
}

void TickLockerModule::onMouseLeftClick(const MouseBlockClickEvent& eventt) {
    if (!this->isEnabled()) return;
    if (eventt.hasBlockPosition()) {
        const auto& clickedPos = eventt.getBlockPosition();

        bool isTargetBlock = (targetBlockPos.x == clickedPos.x &&
                             targetBlockPos.y == clickedPos.y &&
                             targetBlockPos.z == clickedPos.z);

        if (targetBlockPos.x != 0 && !isTargetBlock) {
            const auto mutableEvent = const_cast<MouseBlockClickEvent*>(&eventt);
            mutableEvent->setCancelled(true);
        }
    } else {
        const auto mutableEvent = const_cast<MouseBlockClickEvent*>(&eventt);
        mutableEvent->setCancelled(cancelLeftClick);
    }
}

void TickLockerModule::onRender3d(const Render3dEvent& event) {
    if (!this->isEnabled()) return;
    if (!renderSelectedBlock) return;
    JNIEnv* env = event.getEnv();
    if (!env) return;

    if (targetBlockPos.x == 0 && targetBlockPos.y == 0 && targetBlockPos.z == 0) {
        return;
    }
    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState || !gameState->inGameHasFocus()) {
        return;
    }

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) {
        return;
    }

    RenderManager renderManager = mc.getRenderManager();
    if (renderManager.isNull()) {
        return;
    }

    const Vec3D renderPos = renderManager.getRenderPos();

    calculateBlockBoundingBox(targetBlockPos);

    std::vector<Vec3> adjustedBox;
    for (const auto& corner : blockBoundingBox) {
        adjustedBox.push_back(Vec3(
            corner.x - static_cast<float>(renderPos.x),
            corner.y - static_cast<float>(renderPos.y),
            corner.z - static_cast<float>(renderPos.z)
        ));
    }

    std::vector<float> projectionMatrix = ActiveRenderInfo::GetProjectionMatrix(env);
    std::vector<float> modelViewMatrix = ActiveRenderInfo::GetModelViewMatrix(env);

    if (projectionMatrix.size() != 16 || modelViewMatrix.size() != 16) {
        return;
    }

    RenderUtils::setupOpenGL(projectionMatrix, modelViewMatrix);

    if (showFill) {
        RenderUtils::setColor(fillColor);
        RenderUtils::drawBox3D(adjustedBox.data(), true);
    }

    if (showOutline) {
        glLineWidth(outlineWidth);
        RenderUtils::setColor(outlineColor);
        RenderUtils::drawBox3D(adjustedBox.data(), false);
    }

    RenderUtils::restoreOpenGLState();
    // mc and renderManager local refs are freed by their destructors. Explicit DeleteLocalRef
    // removed: it double-freed the same handle and crashed the Java 25 GC on CheatBreaker.
}

void TickLockerModule::onUpdate(JniScope& scope) {
    Minecraft minecraft = Minecraft::getMinecraft(scope.getEnv());
    if (minecraft.isNull()) {
        return;
    }

    EntityClientPlayerMP thePlayer = minecraft.thePlayer();
    if (thePlayer.isNull()) {
        return;
    }

    PlayerControllerMP playerController = minecraft.playerController();
    if (!playerController.isNull()) {
        float rawDamage = playerController.curBlockDamageMP();
        blockDamagePercent = rawDamage * 9.9f;
    } else {
        blockDamagePercent = 0.0f;
    }

    MovingObjectPosition mouseOver = minecraft.objectMouseOver();
    if (mouseOver.isNull()) {
        return;
    }

    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();

    if (this->targetBlockPosKey != 0 && gameState && gameState->inGameHasFocus()) {
        if (GetAsyncKeyState(this->targetBlockPosKey) & 0x8000) {
            if (!this->targetBlockPosKeyWasPress) {
                if (!mouseOver.isNull() && mouseOver.typeOfHit() == MovingObjectPosition::TypeOfHit::BLOCK) {
                    MovingObjectPosition::position newBlockPos = mouseOver.getPosition();

                    if (targetBlockPos.x != newBlockPos.x ||
                        targetBlockPos.y != newBlockPos.y ||
                        targetBlockPos.z != newBlockPos.z) {

                        if (isBlocking) {
                            cancelLeftClick = false;
                            isBlocking = false;
                            if (isRightClickHeld && mode == 0) {
                                releaseRightClick();
                            }
                        }

                        this->targetBlockPos = newBlockPos;
                        NotificationModule::addCustomNotification(Strings::msgTargetBlockUpdated(), this->SET_COLOR);
                    }
                    else {
                        NotificationModule::addCustomNotification(Strings::msgSameBlockTargeted(), this->SET_COLOR);
                    }
                }
                else {
                    NotificationModule::addCustomNotification(Strings::msgNoBlockTargeted(), this->SET_COLOR);
                }
                this->targetBlockPosKeyWasPress = true;
            }
        }
        else {
            this->targetBlockPosKeyWasPress = false;
        }
    }

    if (!thePlayer.hasWeaponInHand()) {
        if (isRightClickHeld && mode == 0) {
            releaseRightClick();
            cancelLeftClick = false;
            isBlocking = false;
        }
        return;
    }

    MovingObjectPosition::TypeOfHit typeOfHit = mouseOver.typeOfHit();
    if (typeOfHit != MovingObjectPosition::TypeOfHit::BLOCK) {
        if (isBlocking) {
            cancelLeftClick = false;
            isBlocking = false;
            if (isRightClickHeld && mode == 0) {
                releaseRightClick();
            }
        }
        return;
    }

    if (!targetBlockPos.x) {
        return;
    }

    MovingObjectPosition::position blockPos = mouseOver.getPosition();
    if (!blockPos.x) {
        return;
    }

    if (targetBlockPos.x == blockPos.x &&
        targetBlockPos.y == blockPos.y &&
        targetBlockPos.z == blockPos.z) {

        if (isBlocking) {
            cancelLeftClick = false;
            isBlocking = false;
            if (isRightClickHeld && mode == 0) {
                releaseRightClick();
            }
        }
    }
    else {
        if (!isBlocking) {
            cancelLeftClick = true;
            isBlocking = true;
            if (mode == 0) {
                holdRightClick();
            }
        }
    }
}

REGISTER_MODULE_EXCEPT_VERSION(TickLockerModule, ModuleType::TICK_LOCKER, MinecraftVersion::V1_7_10)
