#include "../../includes/event/sub/MouseBlockClickEvent.h"

MouseBlockClickEvent::MouseBlockClickEvent(JNIEnv* env, int x, int y, int z, bool valid)
    : EventBase(env) {
    blockPos.x = x;
    blockPos.y = y;
    blockPos.z = z;
    blockPos.isValid = valid;
}

MouseBlockClickEvent::MouseBlockClickEvent(JNIEnv* env)
    : EventBase(env) {
    blockPos.isValid = false;
}

std::type_index MouseBlockClickEvent::getType() const {
    return std::type_index(typeid(MouseBlockClickEvent));
}
