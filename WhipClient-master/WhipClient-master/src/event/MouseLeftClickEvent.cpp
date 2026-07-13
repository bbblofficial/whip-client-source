#include "../../includes/event/sub/MouseLeftClickEvent.h"

MouseLeftClickEvent::MouseLeftClickEvent(JNIEnv* env)
    : EventBase(env) {
}

std::type_index MouseLeftClickEvent::getType() const {
    return std::type_index(typeid(MouseLeftClickEvent));
}
