#include "../../../../includes/wrapper/minecraft/util/MovingObjectPosition.h"
#include "../../../../includes/wrapper/minecraft/util/Vec3.h"
#include "../../../../includes/wrapper/minecraft/entity/Entity.h"

jfieldID MovingObjectPosition::typeOfHitId = NULL;
jobject MovingObjectPosition::missObj = NULL;
jobject MovingObjectPosition::blockObj = NULL;
jobject MovingObjectPosition::entityObj = NULL;
jfieldID MovingObjectPosition::blockPosId = NULL;
jmethodID MovingObjectPosition::getYMethod = NULL;
jmethodID MovingObjectPosition::getXMethod = NULL;
jmethodID MovingObjectPosition::getZMethod = NULL;
jfieldID MovingObjectPosition::entityHitId = NULL;
jfieldID MovingObjectPosition::hitVecId = NULL;
jmethodID MovingObjectPosition::movingObjectPositionConstructorId = NULL;
jfieldID MovingObjectPosition::sideHitId = NULL;
jmethodID MovingObjectPosition::movingObjectPositionEntityConstructorId = NULL;

Vec3MC MovingObjectPosition::hitVec() {
    if (!hitVecId) hitVecId = mappings->getField("MovingObjectPosition#hitVec");
    jobject obj = this->env->GetObjectField(this->obj, hitVecId);
    if (!obj) return Vec3MC(env, NULL);
    return Vec3MC(this->env, obj);
}

MovingObjectPosition MovingObjectPosition::create(JNIEnv* env, TypeOfHit typeOfHitIn, const Vec3MC& hitVecIn, int sideHitIn, jobject blockPosIn) {
    if (!movingObjectPositionConstructorId) {

        movingObjectPositionConstructorId = mappings->getMethod("MovingObjectPosition#<init>_MovingObjectType_Vec3_I_BlockPos");
    }

    jobject typeObj = nullptr;
    if (!missObj) missObj = mappings->getObject("MovingObjectPosition$MovingObjectType#MISS");
    if (!blockObj) blockObj = mappings->getObject("MovingObjectPosition$MovingObjectType#BLOCK");
    if (!entityObj) entityObj = mappings->getObject("MovingObjectPosition$MovingObjectType#ENTITY");

    switch (typeOfHitIn) {
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

    jobject newObj = env->NewObject(
        mappings->getClass("MovingObjectPosition"),
        movingObjectPositionConstructorId,
        typeObj,
        hitVecIn.getObj(),
        sideHitIn,
        blockPosIn
    );

    if (!newObj) return MovingObjectPosition(env, NULL);
    return MovingObjectPosition(env, newObj);
}

MovingObjectPosition MovingObjectPosition::createFromEntity(JNIEnv* env, const Entity& entityHit, const Vec3MC& hitVec) {
    if (!movingObjectPositionEntityConstructorId) {

        movingObjectPositionEntityConstructorId = mappings->getMethod("MovingObjectPosition#<init>_Entity_Vec3");
    }

    if (!movingObjectPositionEntityConstructorId) {
        MovingObjectPosition mop = createEntityHit(env, hitVec);
        if (mop.isNull()) return mop;
        if (!entityHitId) entityHitId = mappings->getField("MovingObjectPosition#entityHit");
        if (entityHitId) env->SetObjectField(mop.getObj(), entityHitId, entityHit.getObj());
        return mop;
    }

    jobject newObj = env->NewObject(
        mappings->getClass("MovingObjectPosition"),
        movingObjectPositionEntityConstructorId,
        entityHit.getObj(),
        hitVec.getObj()
    );

    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return MovingObjectPosition(env, NULL);
    }
    if (!newObj) return MovingObjectPosition(env, NULL);
    return MovingObjectPosition(env, newObj);
}

MovingObjectPosition MovingObjectPosition::createEntityHit(JNIEnv* env, const Vec3MC& hitVecIn) {
    return create(env, TypeOfHit::ENTITY, hitVecIn, 0, NULL);
}

MovingObjectPosition MovingObjectPosition::createBlockHit(JNIEnv* env, const Vec3MC& hitVecIn, jobject blockPosIn, int sideHit) {
    return create(env, TypeOfHit::BLOCK, hitVecIn, sideHit, blockPosIn);
}
