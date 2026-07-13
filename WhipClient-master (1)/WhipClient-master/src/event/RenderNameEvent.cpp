#include "../../includes/event/sub/RenderNameEvent.h"

RenderNameEvent::RenderNameEvent(JNIEnv* env)
    : EventBase(env) {
}

std::type_index RenderNameEvent::getType() const {
    return std::type_index(typeid(RenderNameEvent));
}
