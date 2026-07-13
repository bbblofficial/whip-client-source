#pragma once
#include "play/server/s12packetentityvelocity.h"
#include "packet.h"

class NetHandlerPlayServer : public JavaObject {
private:
    static jmethodID sendPacketId;

public:
    NetHandlerPlayServer(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    void sendPacket(Packet packet) {
        if (!sendPacketId) sendPacketId = mappings->getMethod("NetHandlerPlayServer#sendPacket");
        this->env->CallVoidMethod(this->obj, sendPacketId, packet.getObj());
    }
};
