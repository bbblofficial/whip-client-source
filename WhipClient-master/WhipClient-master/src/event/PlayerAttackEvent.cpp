#include "../../includes/event/sub/PlayerAttackEvent.h"

PlayerAttackEvent::PlayerAttackEvent(JNIEnv* env, int targetId)
    : EventBase(env), targetId_(targetId) {
}

int PlayerAttackEvent::getTargetEntityId() const {
    return targetId_;
}

std::type_index PlayerAttackEvent::getType() const {
    return std::type_index(typeid(PlayerAttackEvent));
}
