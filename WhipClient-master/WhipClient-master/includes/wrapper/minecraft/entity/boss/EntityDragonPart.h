#pragma once
#include "../entity.h"
#include "../IEntityMultiPart.h"

class EntityDragonPart : public Entity {
private:
    static jfieldID entityDragonObjId;
    static jfieldID getEntityDragonObjId;

public:
    EntityDragonPart(JNIEnv* env, jobject obj) : Entity::Entity(env, obj) {}

    IEntityMultiPart getEntityDragonObj() {
        if (!getEntityDragonObjId) getEntityDragonObjId = mappings->getField("EntityDragonPart#entityDragonObj");
        jobject obj = this->env->GetObjectField(this->obj, getEntityDragonObjId);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }
};
