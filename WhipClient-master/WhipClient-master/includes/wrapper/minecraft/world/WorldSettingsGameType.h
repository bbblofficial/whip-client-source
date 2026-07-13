#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"

class WorldSettingsGameType : public JavaObject {
private:
	static jmethodID isAdventureId;
	static jmethodID isCreativeId;
	static jfieldID ADVENTUREId;
	static jfieldID CREATIVEId;
	static jfieldID NOT_SETId;
	static jfieldID SPECTATORId;
	static jfieldID SURVIVALId;

public:
	WorldSettingsGameType(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

	bool isAdventure() {
		if (!isAdventureId) isAdventureId = mappings->getMethod("WorldSettings$GameType#isAdventure");
		return this->env->CallBooleanMethod(this->obj, isAdventureId);
	}

	bool isCreative() {
		if (!isCreativeId) isCreativeId = mappings->getMethod("WorldSettings$GameType#isCreative");
		return this->env->CallBooleanMethod(this->obj, isCreativeId);
	}

	static WorldSettingsGameType ADVENTURE(JNIEnv* env) {
		if (!ADVENTUREId) ADVENTUREId = mappings->getField("WorldSettings$GameType#ADVENTURE");
		jobject obj = env->GetStaticObjectField(mappings->getClass("WorldSettings$GameType"), ADVENTUREId);
		return { env, obj };
	}

	static WorldSettingsGameType CREATIVE(JNIEnv* env) {
		if (!CREATIVEId) CREATIVEId = mappings->getField("WorldSettings$GameType#CREATIVE");
		jobject obj = env->GetStaticObjectField(mappings->getClass("WorldSettings$GameType"), CREATIVEId);
		return { env, obj };
	}

	static WorldSettingsGameType NOT_SET(JNIEnv* env) {
		if (!NOT_SETId) NOT_SETId = mappings->getField("WorldSettings$GameType#NOT_SET");
		jobject obj = env->GetStaticObjectField(mappings->getClass("WorldSettings$GameType"), NOT_SETId);
		return { env, obj };
	}

	static WorldSettingsGameType SPECTATOR(JNIEnv* env) {
		if (!SPECTATORId) SPECTATORId = mappings->getField("WorldSettings$GameType#SPECTATOR");
		jobject obj = env->GetStaticObjectField(mappings->getClass("WorldSettings$GameType"), SPECTATORId);
		return { env, obj };
	}

	static WorldSettingsGameType SURVIVAL(JNIEnv* env) {
		if (!SURVIVALId) SURVIVALId = mappings->getField("WorldSettings$GameType#SURVIVAL");
		jobject obj = env->GetStaticObjectField(mappings->getClass("WorldSettings$GameType"), SURVIVALId);
		return { env, obj };
	}
};
