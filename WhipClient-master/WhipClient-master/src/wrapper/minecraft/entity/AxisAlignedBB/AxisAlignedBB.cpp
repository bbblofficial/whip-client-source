#include "../../../../../includes/wrapper/minecraft/entity/axisalignedbb/AxisAlignedBB.h"
#include "../../../../../includes/wrapper/minecraft/util/MovingObjectPosition.h"
#include "../../../../../includes/wrapper/minecraft/util/Vec3.h"

jfieldID AxisAlignedBB::minXId = NULL;
jfieldID AxisAlignedBB::minYId = NULL;
jfieldID AxisAlignedBB::minZId = NULL;
jfieldID AxisAlignedBB::maxXId = NULL;
jfieldID AxisAlignedBB::maxYId = NULL;
jfieldID AxisAlignedBB::maxZId = NULL;
jmethodID AxisAlignedBB::addCoordId = NULL;
jmethodID AxisAlignedBB::expandId = NULL;
jmethodID AxisAlignedBB::calculateInterceptId = NULL;
jmethodID AxisAlignedBB::isVecInsideId = NULL;
jmethodID AxisAlignedBB::offsetId = nullptr;

MovingObjectPosition AxisAlignedBB::calculateIntercept(const Vec3MC& startVec, const Vec3MC& endVec) {
    if (!calculateInterceptId) calculateInterceptId = mappings->getMethod("AxisAlignedBB#calculateIntercept");
    jobject result = this->env->CallObjectMethod(this->obj, calculateInterceptId, startVec.getObj(), endVec.getObj());
    if (!result) return MovingObjectPosition(NULL, NULL);
    return MovingObjectPosition(this->env, result);
}

bool AxisAlignedBB::isVecInside(const Vec3MC& vec) {
    if (!isVecInsideId) isVecInsideId = mappings->getMethod("AxisAlignedBB#isVecInside");
    return this->env->CallBooleanMethod(this->obj, isVecInsideId, vec.getObj());
}
