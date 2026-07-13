#pragma once

#include "../../../../includes/wrapper/primitive/JavaObject.h"

class MouvementInput : public JavaObject {
private:
	static jfieldID moveStrafeFid;
	static jfieldID moveForwardFid;

public:
	MouvementInput(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    float getMoveStrafe() {
        if (!moveStrafeFid) moveStrafeFid = mappings->getField("MovementInput#moveStrafe");
        return this->env->GetFloatField(this->obj, moveStrafeFid);
    }

    float getMoveForward() {
        if (!moveForwardFid) moveForwardFid = mappings->getField("MovementInput#moveForward");
        return this->env->GetFloatField(this->obj, moveForwardFid);
    }

    void setMoveStrafe(float moveStrafe) {
        if (!moveStrafeFid) moveStrafeFid = mappings->getField("MovementInput#moveStrafe");
        this->env->SetFloatField(this->obj, moveStrafeFid, moveStrafe);
    }

    void setMoveForward(float moveForward) {
        if (!moveForwardFid) moveForwardFid = mappings->getField("MovementInput#moveForward");
        this->env->SetFloatField(this->obj, moveForwardFid, moveForward);
    }
};
