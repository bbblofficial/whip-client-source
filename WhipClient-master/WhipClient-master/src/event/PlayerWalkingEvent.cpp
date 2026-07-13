#include "../../includes/event/sub/PlayerWalkingEvent.h"

PlayerWalkingEvent::PlayerWalkingEvent(JNIEnv* env)
    : EventBase(env) {

}

std::type_index PlayerWalkingEvent::getType() const {
    return std::type_index(typeid(PlayerWalkingEvent));
}
