#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "wrapper/minecraft/block/Block.h"
#include "wrapper/minecraft/util/BlockPos.h"

class TileEntity : public JavaObject {
    static jmethodID getPosId;
    static jmethodID getBlockTypeId;
    static jfieldID GetxCoordId;
    static jfieldID GetyCoordId;
    static jfieldID GetzCoordId;
public:
    TileEntity(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    BlockPos getPos() {
        if (!getPosId) getPosId = mappings->getMethod("TileEntity#getPos");
        return {env, this->env->CallObjectMethod(this->obj, getPosId)};
    }

    int getX() {
        if (!GetxCoordId) GetxCoordId = mappings->getField("TileEntity#xCoord");
        return this->env->GetIntField(this->obj, GetxCoordId);
    }

    int getY() {
        if (!GetyCoordId) GetyCoordId = mappings->getField("TileEntity#yCoord");
        return this->env->GetIntField(this->obj, GetyCoordId);
    }

    int getZ() {
        if (!GetzCoordId) GetzCoordId = mappings->getField("TileEntity#zCoord");
        return this->env->GetIntField(this->obj, GetzCoordId);
    }

    Block getBlockType() {
        if (!getBlockTypeId) getBlockTypeId = mappings->getMethod("TileEntity#getBlockType");
        jobject obj = this->env->CallObjectMethod(this->obj, getBlockTypeId);
        return {env, obj};
    }
};
