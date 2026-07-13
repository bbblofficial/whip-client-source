#include "../../includes/event/sub/ChannelReadEvent.h"
#include "wrapper/minecraft/network/Packet.h"

ChannelReadEvent::ChannelReadEvent(JNIEnv* env, jobject packetObj)
    : EventBase(env), packetObj(packetObj) {
}

jobject ChannelReadEvent::getPacketObject() const
{
    return packetObj;
}

void ChannelReadEvent::setPacketObject(jobject packetObj)
{
    this->packetObj = packetObj;
}

std::type_index ChannelReadEvent::getType() const {
    return std::type_index(typeid(ChannelReadEvent));
}
