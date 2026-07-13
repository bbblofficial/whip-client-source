#pragma once

#include "../../world/World.h"
#include "../../entity/Entity.h"

class WorldClient : public World {
private:
	static jmethodID getEntityByIDId;
	static jmethodID addEntityToWorldId;
	static jmethodID removeEntityFromWorldId;

public:
	WorldClient(JNIEnv* env, jobject obj) : World::World(env, obj) {}

	Entity getEntityByID(int id) {
		if (!getEntityByIDId) getEntityByIDId = mappings->getMethod("WorldClient#getEntityByID");

		jobject obj = this->env->CallObjectMethod(this->obj, getEntityByIDId, id);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	void addEntityToWorld(int entityId, jobject entity) {
		if (!addEntityToWorldId) addEntityToWorldId = mappings->getMethod("WorldClient#addEntityToWorld");
		this->env->CallVoidMethod(this->obj, addEntityToWorldId, entityId, entity);
	}

	Entity removeEntityFromWorld(int entityId) {
		if (!removeEntityFromWorldId) removeEntityFromWorldId = mappings->getMethod("WorldClient#removeEntityFromWorld");
		jobject obj = this->env->CallObjectMethod(this->obj, removeEntityFromWorldId, entityId);
		if (!obj) return { NULL, NULL };
		return { this->env, obj };
	}
};
