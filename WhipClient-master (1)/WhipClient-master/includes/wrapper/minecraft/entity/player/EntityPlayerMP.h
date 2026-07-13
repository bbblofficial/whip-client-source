#pragma once
#include "EntityPlayer.h"
#include "../../network/NetHandlerPlayServer.h"

class EntityPlayerMP : public EntityPlayer {
private:
    static jfieldID getPlayerNetServerHandlerId;

public:
    EntityPlayerMP(JNIEnv* env, jobject obj) : EntityPlayer::EntityPlayer(env, obj) {}

    NetHandlerPlayServer getPlayerNetServerHandler() {
        if (!getPlayerNetServerHandlerId) getPlayerNetServerHandlerId = mappings->getField("EntityPlayerMP#playerNetServerHandler");
        jobject obj = this->env->GetObjectField(this->obj, getPlayerNetServerHandlerId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }
};
