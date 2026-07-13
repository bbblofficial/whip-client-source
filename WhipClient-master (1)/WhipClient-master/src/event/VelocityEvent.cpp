#include "../../includes/event/sub/VelocityEvent.h"

VelocityEvent::VelocityEvent(JNIEnv* env, S12PacketEntityVelocity& entityVelo)
    : EventBase(env), entityVelo(entityVelo){
}

S12PacketEntityVelocity VelocityEvent::getVeloPacket()
{
    return entityVelo;
}

S12PacketEntityVelocity VelocityEvent::setVeloPacket(const S12PacketEntityVelocity& packet)
{
    return entityVelo = packet;
}

std::type_index VelocityEvent::getType() const {
    return std::type_index(typeid(VelocityEvent));
}
