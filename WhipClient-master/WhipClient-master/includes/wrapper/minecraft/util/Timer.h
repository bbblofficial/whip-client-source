#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"

class Timer : public JavaObject {
private:

	static jfieldID PartialTickID;
	static jfieldID TimerSpeedID;
	static jfieldID TicksPerSecondID;

public:
	Timer(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

	float GetrenderPartialTicks() {
		if (!PartialTickID) PartialTickID = mappings->getField("Timer#renderPartialTicks");
		return this->env->GetFloatField(this->obj, PartialTickID);
	}

	float getTimerSpeed() {
		if (!TimerSpeedID) TimerSpeedID = mappings->getField("Timer#timerSpeed");
		return this->env->GetFloatField(this->obj, TimerSpeedID);
	}

	void setTimerSpeed(float speed) {
		if (!TimerSpeedID) TimerSpeedID = mappings->getField("Timer#timerSpeed");
		this->env->SetFloatField(this->obj, TimerSpeedID, speed);
	}

	float getTicksPerSecond() {
		if (!TicksPerSecondID) TicksPerSecondID = mappings->getField("Timer#ticksPerSecond");
		return this->env->GetFloatField(this->obj, TicksPerSecondID);
	}

	void setTicksPerSecond(float tps) {
		if (!TicksPerSecondID) TicksPerSecondID = mappings->getField("Timer#ticksPerSecond");
		this->env->SetFloatField(this->obj, TicksPerSecondID, tps);
	}

};
