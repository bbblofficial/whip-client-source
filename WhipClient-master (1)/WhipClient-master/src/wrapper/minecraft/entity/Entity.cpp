#include "../../../../includes/wrapper/minecraft/entity/Entity.h"
#include "../../../../includes/wrapper/minecraft/util/DamageSource.h"
#include "../../../../includes/wrapper/minecraft/util/MovingObjectPosition.h"
#include "../../../../includes/wrapper/minecraft/util/Vec3.h"
#include "wrapper/minecraft/world/World.h"

jfieldID Entity::posXId = NULL;
jfieldID Entity::posYId = NULL;
jfieldID Entity::posZId = NULL;
jfieldID Entity::lastTickposXId = NULL;
jfieldID Entity::lastTickposYId = NULL;
jfieldID Entity::lastTickposZId = NULL;
jfieldID Entity::motionXId = NULL;
jfieldID Entity::motionYId = NULL;
jfieldID Entity::motionZId = NULL;
jfieldID Entity::setmotionXId = NULL;
jfieldID Entity::setmotionZId = NULL;
jfieldID Entity::setmotionYId = NULL;
jfieldID Entity::serverPosXId = NULL;
jfieldID Entity::serverPosYId = NULL;
jfieldID Entity::serverPosZId = NULL;
jfieldID Entity::rotationYawId = NULL;
jfieldID Entity::rotationPitchId = NULL;
jfieldID Entity::prevRotationYawId = NULL;
jmethodID Entity::getEyeHeightId = NULL;
jfieldID Entity::prevRotationPitchId = NULL;
jmethodID Entity::getFormattedCommandSenderNameId = NULL;
jmethodID Entity::isSprintingId = NULL;
jfieldID Entity::onGroundId = NULL;
jmethodID Entity::setSprintingId = NULL;
jmethodID Entity::setAnglesId = NULL;
jclass Entity::entityPlayerClass = NULL;
jclass Entity::entityLivingBaseClass = NULL;
jfieldID Entity::entityIdId = NULL;
jfieldID Entity::boundingBoxId = NULL;
jmethodID Entity::getNameId = NULL;
jfieldID Entity::worldObjId = NULL;
jfieldID Entity::hurtResistantTimeId = NULL;
jmethodID Entity::canAttackWithItemId = NULL;
jmethodID Entity::hitByEntityId = NULL;
jfieldID Entity::velocityChangedId = NULL;
jmethodID Entity::setFireId = NULL;
jmethodID Entity::isBurningId = NULL;
jmethodID Entity::extinguishId = NULL;
jmethodID Entity::attackEntityFromId = NULL;
jmethodID Entity::addVelocityId = NULL;
jfieldID Entity::setVelocityChangedId = NULL;
jfieldID Entity::getFallDistanceId = NULL;
jmethodID Entity::rayTraceId = NULL;
jmethodID Entity::getPositionEyesId = NULL;
jmethodID Entity::getLookId;
jmethodID Entity::canBeCollidedWithId = NULL;
jmethodID Entity::getCollisionBorderSizeId = NULL;
jmethodID Entity::getEntityBoundingBoxId = NULL;
jfieldID Entity::ridingEntityId = NULL;
jfieldID Entity::entityUniqueIDId = NULL;
jmethodID Entity::setVelocityId = NULL;
jmethodID Entity::isSneakingId = NULL;
jmethodID Entity::getPositionId = NULL;
jmethodID Entity::getCommandSenderNameId = NULL;
jfieldID Entity::isDeadid = NULL;
jmethodID Entity::getPositionVectorId = NULL;
jmethodID Entity::isInvisibleId = NULL;
jmethodID Entity::hasCustomNameId = NULL;
jfieldID Entity::ticksExistedId = NULL;

bool Entity::attackEntityFrom(DamageSource source, float amount) {
    if (!attackEntityFromId) attackEntityFromId = mappings->getMethod("Entity#attackEntityFrom");
    return this->env->CallBooleanMethod(this->obj, attackEntityFromId, source.getObj(), amount);
}

MovingObjectPosition Entity::rayTrace(double distance, float partialTicks) {
    if (!rayTraceId) rayTraceId = mappings->getMethod("Entity#rayTrace");
    jobject result = this->env->CallObjectMethod(this->obj, rayTraceId, distance, partialTicks);
    if (!result) return MovingObjectPosition(env, NULL);
    return MovingObjectPosition(this->env, result);
}

Vec3MC Entity::getPositionEyes(float partialTicks) {
    if (!getPositionEyesId) getPositionEyesId = mappings->getMethod("Entity#getPositionEyes");
    jobject result = this->env->CallObjectMethod(this->obj, getPositionEyesId, partialTicks);
    return Vec3MC(this->env, result);
}

Vec3MC Entity::getPosition(float partialTicks) {
    if (!getPositionId) getPositionId = mappings->getMethod("C07PacketPlayerDigging#getPosition");
    jobject result = this->env->CallObjectMethod(this->obj, getPositionId, partialTicks);
    if (!result) return Vec3MC(env, NULL);
    return Vec3MC(this->env, result);
}

Vec3MC Entity::getLook(float partialTicks) {
    if (!getLookId) getLookId = mappings->getMethod("Entity#getLook");
    jobject result = this->env->CallObjectMethod(this->obj, getLookId, partialTicks);
    if (!result) return Vec3MC(env, NULL);
    return Vec3MC(this->env, result);
}

AxisAlignedBB Entity::getEntityBoundingBox() {
    if (!getEntityBoundingBoxId) getEntityBoundingBoxId = mappings->getMethod("Entity#getEntityBoundingBox");
    jobject result = this->env->CallObjectMethod(this->obj, getEntityBoundingBoxId);
    if (!result) return AxisAlignedBB(NULL, NULL);
    return AxisAlignedBB(this->env, result);
}

World Entity::worldObj() {
    if (!worldObjId) worldObjId = mappings->getField("Entity#worldObj");

    jobject obj = this->env->GetObjectField(this->obj, worldObjId);
    if (!obj) return World{ env, NULL };

    return World{ this->env, obj };
}
