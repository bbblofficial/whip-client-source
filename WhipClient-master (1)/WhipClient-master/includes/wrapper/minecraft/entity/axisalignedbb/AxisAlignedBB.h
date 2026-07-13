#pragma once
#include "../../../../../includes/wrapper/primitive/JavaObject.h"

class MovingObjectPosition;
class Vec3MC;

class AxisAlignedBB : public JavaObject {
private:
    static jfieldID minXId;
    static jfieldID minYId;
    static jfieldID minZId;
    static jfieldID maxXId;
    static jfieldID maxYId;
    static jfieldID maxZId;
    static jmethodID addCoordId;
    static jmethodID expandId;
    static jmethodID offsetId;
    static jmethodID calculateInterceptId;
    static jmethodID isVecInsideId;

public:
    AxisAlignedBB(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    double getMinX() const {
        if (!minXId) minXId = mappings->getField("AxisAlignedBB#minX");
        return this->env->GetDoubleField(this->obj, minXId);
    }

    double getMinY() const {
        if (!minYId) minYId = mappings->getField("AxisAlignedBB#minY");
        return this->env->GetDoubleField(this->obj, minYId);
    }

    double getMinZ() const {
        if (!minZId) minZId = mappings->getField("AxisAlignedBB#minZ");
        return this->env->GetDoubleField(this->obj, minZId);
    }

    double getMaxX() const {
        if (!maxXId) maxXId = mappings->getField("AxisAlignedBB#maxX");
        return this->env->GetDoubleField(this->obj, maxXId);
    }

    double getMaxY() const {
        if (!maxYId) maxYId = mappings->getField("AxisAlignedBB#maxY");
        return this->env->GetDoubleField(this->obj, maxYId);
    }

    double getMaxZ() const {
        if (!maxZId) maxZId = mappings->getField("AxisAlignedBB#maxZ");
        return this->env->GetDoubleField(this->obj, maxZId);
    }

    void setMinX(double value) {
        if (!minXId) minXId = mappings->getField("AxisAlignedBB#minX");
        this->env->SetDoubleField(this->obj, minXId, value);
    }

    void setMinY(double value) {
        if (!minYId) minYId = mappings->getField("AxisAlignedBB#minY");
        this->env->SetDoubleField(this->obj, minYId, value);
    }

    void setMinZ(double value) {
        if (!minZId) minZId = mappings->getField("AxisAlignedBB#minZ");
        this->env->SetDoubleField(this->obj, minZId, value);
    }

    void setMaxX(double value) {
        if (!maxXId) maxXId = mappings->getField("AxisAlignedBB#maxX");
        this->env->SetDoubleField(this->obj, maxXId, value);
    }

    void setMaxY(double value) {
        if (!maxYId) maxYId = mappings->getField("AxisAlignedBB#maxY");
        this->env->SetDoubleField(this->obj, maxYId, value);
    }

    void setMaxZ(double value) {
        if (!maxZId) maxZId = mappings->getField("AxisAlignedBB#maxZ");
        this->env->SetDoubleField(this->obj, maxZId, value);
    }

    double getXWidth() {
        return getMaxX() - getMinX();
    }

    double getZWidth() {
        return getMaxZ() - getMinZ();
    }

    double getHeight() {
        return getMaxY() - getMinY();
    }

    AxisAlignedBB addCoord(double x, double y, double z) {
        if (!addCoordId) addCoordId = mappings->getMethod("AxisAlignedBB#addCoord");
        jobject result = this->env->CallObjectMethod(this->obj, addCoordId, x, y, z);
        if (!result) return AxisAlignedBB(NULL, NULL);
        return AxisAlignedBB(this->env, result);
    }

    AxisAlignedBB expand(double x, double y, double z) {
        if (!expandId) expandId = mappings->getMethod("AxisAlignedBB#expand");
        jobject result = this->env->CallObjectMethod(this->obj, expandId, x, y, z);
        if (!result) return AxisAlignedBB(NULL, NULL);
        return AxisAlignedBB(this->env, result);
    }

    AxisAlignedBB offset(double x, double y, double z) {
        if (!offsetId) offsetId = mappings->getMethod("AxisAlignedBB#offset");
        jobject result = this->env->CallObjectMethod(this->obj, offsetId, x, y, z);
        if (!result) return AxisAlignedBB(NULL, NULL);
        return AxisAlignedBB(this->env, result);
    }

    MovingObjectPosition calculateIntercept(const Vec3MC& startVec, const Vec3MC& endVec);
    bool isVecInside(const Vec3MC& vec);
};
