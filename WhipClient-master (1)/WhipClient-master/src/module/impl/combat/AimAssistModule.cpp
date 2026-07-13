#include "../../../../includes/module/impl/combat/AimAssistModule.h"
#include "wrapper/minecraft/client/minecraft.h"
#include "util/Debug.h"

#define MAXV 80
#define MINV 50
#define MINF 0.10f
#define MAXF 0.15f

AimAssistModule::AimAssistModule() = default;

void AimAssistModule::onUpdate(JniScope& scope) {
    if (this->keepOnTargetKeybind != 0) {
        const bool isPressed = (GetAsyncKeyState(this->keepOnTargetKeybind) & 0x8000) != 0;
        if (isPressed && !this->keepOnTargetKeybindPressed) {
            this->keepOnTarget = !this->keepOnTarget;
            this->keepOnTargetKeybindPressed = true;
        } else if (!isPressed && this->keepOnTargetKeybindPressed) {
            this->keepOnTargetKeybindPressed = false;
        }
    }

    Minecraft theMc = Minecraft::getMinecraft(scope.getEnv());
    if (theMc.isNull()) {
        this->updateRandomSpeed(false);
        return;
    }

    GameSettings gameSettings = theMc.gameSettings();
    WorldClient theWorld = theMc.theWorld();
    EntityClientPlayerMP thePlayer = theMc.thePlayer();
    MovingObjectPosition movingObjectPosition = theMc.objectMouseOver();

    if (theWorld.isNull()
        || thePlayer.isNull()
        || gameSettings.isNull()
        || movingObjectPosition.isNull()
        || !theMc.inGameHasFocus()
    ) {
        this->updateRandomSpeed(false);
        return;
    }

    const bool clickOk  = !this->requireClick || (GetKeyState(MK_LBUTTON) & 0x8000) != 0;
    const bool weaponOk = !this->weaponsOnly  || thePlayer.hasWeaponInHand();

    if (const bool blockOk  = !this->breakBlock   || movingObjectPosition.typeOfHit() != MovingObjectPosition::TypeOfHit::BLOCK; !clickOk || !weaponOk || !blockOk) {
        if (this->lastTarget.entityId != -1)
            this->lastTarget = { -1, 0.0, 0.0f, 0.0f };
        this->updateRandomSpeed(false);
        return;
    }

    const Target target = this->getTarget(theWorld, thePlayer);
    if (target.entityId == -1) {
        this->updateRandomSpeed(false);
        return;
    }

    if (target.entityId != this->lastTarget.entityId) {
        this->multipointSignX = (randomInt(0, 1) == 0) ? -1 : 1;
        this->multipointSignZ = (randomInt(0, 1) == 0) ? -1 : 1;
    }

    float deltaYaw = 0.0f, deltaPitch = 0.0f;

    deltaYaw = target.yaw * (this->randomSpeed / 50.0f * sqrt(this->lastTarget.distance));
    deltaYaw = (target.yaw < 0.0f ? -1.0f : 1.0f) * std::clamp(abs(deltaYaw), 0.0f, abs(target.yaw));

    const float var3 = gameSettings.mouseSensitivity() * 0.6f + 0.2f;
    const float var4 = var3 * var3 * var3 * 8.0f;

    const int deltaX = static_cast<int>(round(deltaYaw / var4));
    deltaYaw = deltaX * var4;

    if (abs(deltaYaw) >= 0.0f) {
        if (this->cycledH) {
            this->maxAddedH = randomFloat(MINV, MAXV);
            this->cycledH = false;
            this->addedH = 0.0f;
        }

        deltaPitch = this->upH ? abs(randomFloat(MINF, MAXF)) : -abs(randomFloat(MINF, MAXF));
        deltaPitch = deltaPitch * abs(deltaYaw);

        this->addedH += deltaPitch;

        if (abs(this->addedH) > this->maxAddedH) {
            this->upH = !this->upH;
            this->cycledH = !this->cycledH;
        }

        const int deltaY = static_cast<int>(round(deltaPitch / var4));
        deltaPitch = deltaY * var4;
    }

    thePlayer.setAngles(deltaYaw, deltaPitch);

    this->lastTarget = target;
    this->updateRandomSpeed(true);
}

void AimAssistModule::updateRandomSpeed(bool success) {
    if (!success)
        return;

    if (this->nextRandomSpeed > 0) {
        this->nextRandomSpeed--;

        return;
    }

    if (this->exhaust && randomInt(0, 100) < 50) {
        this->randomSpeed = randomFloat(this->speed * 0.25f, this->speed * 0.5f);
    } else {
        this->randomSpeed = randomFloat(this->speed * 0.5f, this->speed);
    }

    this->nextRandomSpeed = randomInt(400, 750);
}

REGISTER_MODULE(AimAssistModule, ModuleType::AIM_ASSIST)
