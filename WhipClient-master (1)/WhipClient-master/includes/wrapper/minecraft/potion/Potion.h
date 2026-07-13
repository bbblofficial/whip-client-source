#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"

class Potion : public JavaObject {
private:
    static jclass potionClass;
    static jfieldID blindnessId;
    static jobject blindnessCached;

public:
    Potion(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    static Potion blindness(JNIEnv* env) {
        if (!env) return { NULL, NULL };

        if (blindnessCached) {
            Potion wrapper{ env, blindnessCached };
            wrapper.setDeleteRef(false);
            return wrapper;
        }

        if (!potionClass) potionClass = mappings->getClass("Potion");
        if (!blindnessId) blindnessId = mappings->getField("Potion#blindness");

        jobject local = env->GetStaticObjectField(potionClass, blindnessId);
        if (!local) return { NULL, NULL };

        blindnessCached = env->NewGlobalRef(local);
        env->DeleteLocalRef(local);

        Potion wrapper{ env, blindnessCached };
        wrapper.setDeleteRef(false);
        return wrapper;
    }
};
