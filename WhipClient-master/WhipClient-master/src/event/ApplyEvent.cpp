#include "../../includes/event/sub/ApplyEvent.h"

ApplyEvent::ApplyEvent(JNIEnv* env, Entity& p_apply_1_, bool value)
    : EventBase(env), p_apply_1_(p_apply_1_), value(value) {

}

Entity& ApplyEvent::getApply() {
    return p_apply_1_;
}

void ApplyEvent::setApply(Entity& apply) {
    p_apply_1_ = apply;
}

bool ApplyEvent::getValue()
{
    return value;
}

void ApplyEvent::setValue(bool val)
{
    value = val;
}

std::type_index ApplyEvent::getType() const {
    return std::type_index(typeid(ApplyEvent));
}
