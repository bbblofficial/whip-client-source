#pragma once
#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../enchantment/EnchantmentHelper.h"
#include "../../entity/Entity.h"

class EntityRenderer : public JavaObject {
private:
	static jfieldID pointedEntityId;

public:
	EntityRenderer() : JavaObject::JavaObject(nullptr, nullptr) {}
	EntityRenderer(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

	jobject pointedEntity() {
		if (!pointedEntityId) pointedEntityId = mappings->getField("EntityRenderer#pointedEntity");

		jobject obj = this->env->GetObjectField(this->obj, pointedEntityId);
		if (!obj) return { NULL };

		return obj;
	}

	void setPointedEntity(Entity entity) {
		if (!pointedEntityId) pointedEntityId = mappings->getField("EntityRenderer#pointedEntity");

		this->env->SetObjectField(this->obj, pointedEntityId, entity.getObj());
	}

	void setPointedEntity() {
		if (!pointedEntityId) pointedEntityId = mappings->getField("EntityRenderer#pointedEntity");

		this->env->SetObjectField(this->obj, pointedEntityId, NULL);
	}
};
