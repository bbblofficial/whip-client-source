#include "../../includes/event/sub/AttackEntityEvent.h"

AttackEntityEvent::AttackEntityEvent(JNIEnv* env, float retainedSpeed, jobject target)
    : EventBase(env), retainedSpeed(retainedSpeed), target(target) {

}

float AttackEntityEvent::getRetainedSpeed() const {
    return retainedSpeed;
}

void AttackEntityEvent::setRetainedSpeed(float retainedSpeed) {
    this->retainedSpeed = retainedSpeed;
}

std::type_index AttackEntityEvent::getType() const {
    return std::type_index(typeid(AttackEntityEvent));
}
