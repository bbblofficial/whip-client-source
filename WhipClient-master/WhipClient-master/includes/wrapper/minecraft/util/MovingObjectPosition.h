#pragma once

#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "../entity/Entity.h"

class Vec3MC;

class MovingObjectPosition : public JavaObject {
    static jfieldID typeOfHitId;
    static jfieldID blockPosId;
    static jfieldID hitVecId;
    static jobject missObj;
    static jobject blockObj;
    static jobject entityObj;
    static jmethodID getXMethod;
    static jmethodID getYMethod;
    static jmethodID getZMethod;
    static jfieldID entityHitId;
    static jmethodID movingObjectPositionConstructorId;
    static jfieldID sideHitId;
    static jmethodID movingObjectPositionEntityConstructorId;

public:
    struct position {
        int x, y, z;
    };

    enum class TypeOfHit {
        MISS = 0, BLOCK = 1, ENTITY = 2
    };

    MovingObjectPosition(JNIEnv* env, jobject obj) : JavaObject(env, obj) {
        if (env && obj && MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
            if (!blockPosId) blockPosId = mappings->getField("MovingObjectPosition#blockPos");
        }
    }

    TypeOfHit typeOfHit() {
        if (!typeOfHitId) typeOfHitId = mappings->getField("MovingObjectPosition#typeOfHit");
        if (!missObj) missObj = mappings->getObject("MovingObjectPosition$MovingObjectType#MISS");
        if (!blockObj) blockObj = mappings->getObject("MovingObjectPosition$MovingObjectType#BLOCK");
        if (!entityObj) entityObj = mappings->getObject("MovingObjectPosition$MovingObjectType#ENTITY");

        jobject obj = this->env->GetObjectField(this->obj, typeOfHitId);
        TypeOfHit result = TypeOfHit::MISS;

        if (!obj || this->env->IsSameObject(obj, missObj))
            result = TypeOfHit::MISS;
        else if (this->env->IsSameObject(obj, blockObj))
            result = TypeOfHit::BLOCK;
        else if (this->env->IsSameObject(obj, entityObj))
            result = TypeOfHit::ENTITY;

        if (obj) this->env->DeleteLocalRef(obj);
        return result;
    }

    void setTypeOfHit(TypeOfHit type) {
        if (!typeOfHitId) typeOfHitId = mappings->getField("MovingObjectPosition#typeOfHit");
        if (!missObj) missObj = mappings->getObject("MovingObjectPosition$MovingObjectType#MISS");
        if (!blockObj) blockObj = mappings->getObject("MovingObjectPosition$MovingObjectType#BLOCK");
        if (!entityObj) entityObj = mappings->getObject("MovingObjectPosition$MovingObjectType#ENTITY");

        jobject typeObj = nullptr;
        switch (type) {
        case TypeOfHit::ENTITY:
            typeObj = entityObj;
            break;
        case TypeOfHit::BLOCK:
            typeObj = blockObj;
            break;
        case TypeOfHit::MISS:
            typeObj = missObj;
            break;
        }
        this->env->SetObjectField(this->obj, typeOfHitId, typeObj);
    }

    Entity entityHit() {
        if (!entityHitId) entityHitId = mappings->getField("MovingObjectPosition#entityHit");

        jobject obj = this->env->GetObjectField(this->obj, entityHitId);
        if (!obj) return Entity(this->env, NULL);

        return Entity(this->env, obj);
    }

    position getPosition() {
        position pos = { 0, 0, 0 };

        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
            if (!blockPosId) {
                blockPosId = mappings->getField("MovingObjectPosition#blockPos");
            }
            if (!blockPosId) return pos;

            jobject blockPosObj = this->env->GetObjectField(this->obj, blockPosId);
            if (!blockPosObj) {
                return pos;
            }
            if (!getXMethod) getXMethod = mappings->getMethod("Vec3i#getX");
            if (!getYMethod) getYMethod = mappings->getMethod("Vec3i#getY");
            if (!getZMethod) getZMethod = mappings->getMethod("Vec3i#getZ");

            if (getXMethod && getYMethod && getZMethod) {
                pos.x = this->env->CallIntMethod(blockPosObj, getXMethod);
                pos.y = this->env->CallIntMethod(blockPosObj, getYMethod);
                pos.z = this->env->CallIntMethod(blockPosObj, getZMethod);
            }
            this->env->DeleteLocalRef(blockPosObj);
        }
        else if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
            static jfieldID blockXId = nullptr;
            static jfieldID blockYId = nullptr;
            static jfieldID blockZId = nullptr;
            if (!blockXId) blockXId = mappings->getField("MovingObjectPosition#blockX");
            if (!blockYId) blockYId = mappings->getField("MovingObjectPosition#blockY");
            if (!blockZId) blockZId = mappings->getField("MovingObjectPosition#blockZ");

            if (blockXId && blockYId && blockZId) {
                pos.x = this->env->GetIntField(this->obj, blockXId);
                pos.y = this->env->GetIntField(this->obj, blockYId);
                pos.z = this->env->GetIntField(this->obj, blockZId);
            }
        }

        return pos;
    }

    Vec3MC hitVec();

    jobject sideHit() {
        if (!sideHitId) sideHitId = mappings->getField("MovingObjectPosition#sideHit");
        return this->env->GetObjectField(this->obj, sideHitId);
    }

    static MovingObjectPosition create(JNIEnv* env, TypeOfHit typeOfHitIn, const Vec3MC& hitVecIn, int sideHitIn, jobject blockPosIn);
    static MovingObjectPosition createFromEntity(JNIEnv* env, const Entity& entityHit, const Vec3MC& hitVec);
    static MovingObjectPosition createEntityHit(JNIEnv* env, const Vec3MC& hitVecIn);
    static MovingObjectPosition createBlockHit(JNIEnv* env, const Vec3MC& hitVecIn, jobject blockPosIn, int sideHit = 0);
};
