#include "../../includes/event/sub/CanBeCollidedWithEvent.h"

CanBeCollidedWithEvent::CanBeCollidedWithEvent(JNIEnv* env, Entity& p_apply_1_, bool value)
    : EventBase(env), p_apply_1_(p_apply_1_), value(value) {
}

Entity& CanBeCollidedWithEvent::getApply() {
    return p_apply_1_;
}

void CanBeCollidedWithEvent::setApply(Entity& apply) {
    p_apply_1_ = apply;
}

bool CanBeCollidedWithEvent::getValue()
{
    return value;
}

void CanBeCollidedWithEvent::setValue(bool val)
{
    value = val;
}

std::type_index CanBeCollidedWithEvent::getType() const {
    return std::type_index(typeid(CanBeCollidedWithEvent));
}
