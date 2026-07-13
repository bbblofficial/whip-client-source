#include "../../includes/event/sub/OnTickEvent.h"

OnTickEvent::OnTickEvent(JNIEnv* env)
    : EventBase(env) {
}

std::type_index OnTickEvent::getType() const {
    return std::type_index(typeid(OnTickEvent));
}
