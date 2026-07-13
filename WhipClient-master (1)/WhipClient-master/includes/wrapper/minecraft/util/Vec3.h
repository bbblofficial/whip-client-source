#pragma once

#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../../includes/util/MinecraftDetails.h"

class Vec3MC : public JavaObject {

private:
    static jfieldID xCoordId;
    static jfieldID yCoordId;
    static jfieldID zCoordId;
    static jfieldID GetxCoordId;
    static jfieldID GetyCoordId;
    static jfieldID GetzCoordId;
    static jmethodID vec3dConstructor;
    static jmethodID createVectorHelperId;
    static jmethodID distanceToId;
    static jmethodID addVectorId;

public:
    Vec3MC(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {
    }

    Vec3MC(JNIEnv* env, double x, double y, double z) : JavaObject::JavaObject(env, obj) {
        Vec3MC temp = createVec3(env, x, y, z);
        this->env = env;
        this->obj = temp.getObj();
    }

    double getX() {
        if (!GetxCoordId) GetxCoordId = mappings->getField("Vec3#xCoord");
        if (this->isNull()) return NULL;
        return this->env->GetDoubleField(this->obj, GetxCoordId);
    }

    double getY() {
        if (!GetyCoordId) GetyCoordId = mappings->getField("Vec3#yCoord");
        return this->env->GetDoubleField(this->obj, GetyCoordId);
    }

    double getZ() {
        if (!GetzCoordId) GetzCoordId = mappings->getField("Vec3#zCoord");
        return this->env->GetDoubleField(this->obj, GetzCoordId);
    }

    void setX(double x) {
        if (!xCoordId) xCoordId = mappings->getField("Vec3#xCoord");
        this->env->SetDoubleField(this->obj, xCoordId, x);
    }

    void setY(double y) {
        if (!yCoordId) yCoordId = mappings->getField("Vec3#yCoord");
        this->env->SetDoubleField(this->obj, yCoordId, y);
    }

    void setZ(double z) {
        if (!zCoordId) zCoordId = mappings->getField("Vec3#zCoord");
        this->env->SetDoubleField(this->obj, zCoordId, z);
    }

    static Vec3MC createVec3(JNIEnv* env, double x, double y, double z) {
        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
            if (!createVectorHelperId) createVectorHelperId = mappings->getMethod("Vec3#createVectorHelper");
            jclass vec3Class = mappings->getClass("Vec3");
            jobject obj = env->CallStaticObjectMethod(vec3Class, createVectorHelperId, x, y, z);
            return { env, obj };
        }
        if (!vec3dConstructor) vec3dConstructor = mappings->getMethod("Vec3#<init>");
        jobject obj = env->NewObject(mappings->getClass("Vec3"), vec3dConstructor, x, y, z);
        return { env, obj };
    }

    double distanceTo(const Vec3MC& vec) {
        if (!distanceToId) distanceToId = mappings->getMethod("Vec3#distanceTo");
        return this->env->CallDoubleMethod(this->obj, distanceToId, vec.getObj());
    }

    Vec3MC addVector(double x, double y, double z) {
        if (!addVectorId) addVectorId = mappings->getMethod("Vec3#addVector");
        jobject result = this->env->CallObjectMethod(this->obj, addVectorId, x, y, z);

        if (!result) {
            return Vec3MC(this->env, 0.0, 0.0, 0.0);
        }

        Vec3MC tempVec(this->env, result);
        double newX = tempVec.getX();
        double newY = tempVec.getY();
        double newZ = tempVec.getZ();

        return Vec3MC(this->env, newX, newY, newZ);
    }
};
