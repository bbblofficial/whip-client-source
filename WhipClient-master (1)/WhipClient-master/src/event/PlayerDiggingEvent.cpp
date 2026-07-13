#include "../../includes/event/sub/PlayerDiggingEvent.h"

PlayerDiggingEvent::PlayerDiggingEvent(JNIEnv* env, C07PacketPlayerDigging& entityVelo)
    : EventBase(env), playerDigging(entityVelo){
}

C07PacketPlayerDigging PlayerDiggingEvent::getVeloPacket()
{
    return playerDigging;
}

std::type_index PlayerDiggingEvent::getType() const {
    return std::type_index(typeid(PlayerDiggingEvent));
}
