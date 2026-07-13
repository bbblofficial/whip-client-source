#include "event/sub/EntityLivingUpdateEvent.h"

EntityLivingUpdateEvent::EntityLivingUpdateEvent(JNIEnv *env, float moveForward, float moveStrafe, bool shouldApplySlow, bool QuickAccel, bool stop)
    : EventBase(env), moveForward(moveForward), moveStrafe(moveStrafe), shouldApplySlow(shouldApplySlow), QuickAccel(QuickAccel), stop(stop) {
}

float EntityLivingUpdateEvent::getMoveForward() const {
    return moveForward;
}

void EntityLivingUpdateEvent::setMoveForward(const float value) {
    moveForward = value;
}

float EntityLivingUpdateEvent::getMoveStrafe() const {
    return moveStrafe;
}

void EntityLivingUpdateEvent::setMoveStrafe(const float value) {
    moveStrafe = value;
}

bool EntityLivingUpdateEvent::getshouldApplySlow() const {
    return shouldApplySlow;
}

void EntityLivingUpdateEvent::setshouldApplySlow(bool value) {
    shouldApplySlow = value;
}

bool EntityLivingUpdateEvent::getQuickAccel() const {
    return QuickAccel;
}

void EntityLivingUpdateEvent::setQuickAccel(const bool value) {
    QuickAccel = value;
}

void EntityLivingUpdateEvent::setStop(bool value) {
    stop = value;
}

bool EntityLivingUpdateEvent::isStop() const {
    return stop;
}

std::type_index EntityLivingUpdateEvent::getType() const {
    return typeid(EntityLivingUpdateEvent);
}
