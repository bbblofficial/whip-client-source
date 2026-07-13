#pragma once
#include "entity.h"
#include "ai/attributes/IAttribute.h"

class SharedMonsterAttributes : public JavaObject {
    static jclass sharedMonsterAttributesClass;
    static jfieldID attackDamageId;
    static jobject attackDamageCached;

public:
	SharedMonsterAttributes(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    static IAttribute AttackDamage(JNIEnv* env) {
        if (!env) {
            return { nullptr, nullptr };
        }

        if (attackDamageCached) {
            IAttribute wrapper{ env, attackDamageCached };
            wrapper.setDeleteRef(false);
            return wrapper;
        }

        if (!sharedMonsterAttributesClass) {
            sharedMonsterAttributesClass = mappings->getClass("SharedMonsterAttributes");
            if (!sharedMonsterAttributesClass) {
                return { env, nullptr };
            }
        }

        if (!attackDamageId) {
            attackDamageId = mappings->getField("SharedMonsterAttributes#attackDamage");
            if (!attackDamageId) {
                return { env, nullptr };
            }
        }

        jobject local = env->GetStaticObjectField(sharedMonsterAttributesClass, attackDamageId);
        if (!local) {
            return { env, nullptr };
        }

        attackDamageCached = env->NewGlobalRef(local);
        env->DeleteLocalRef(local);

        IAttribute wrapper{ env, attackDamageCached };
        wrapper.setDeleteRef(false);
        return wrapper;
    }

};
