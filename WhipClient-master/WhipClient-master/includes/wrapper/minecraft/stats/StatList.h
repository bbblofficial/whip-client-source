#pragma once
#include "../../../../includes/wrapper/primitive/javaobject.h"
#include "StatBase.h"

class StatList : public JavaObject {
private:
    static jclass statListClass;
    static jfieldID damageDealtStatId;
    static jobject damageDealtStatCached;

public:
    StatList(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    static StatBase damageDealtStat(JNIEnv* env) {
        if (!env) return { NULL, NULL };

        if (damageDealtStatCached) {
            StatBase wrapper{ env, damageDealtStatCached };
            wrapper.setDeleteRef(false);
            return wrapper;
        }

        if (!statListClass) statListClass = mappings->getClass("StatList");
        if (!damageDealtStatId) damageDealtStatId = mappings->getField("StatList#damageDealtStat");

        jobject local = env->GetStaticObjectField(statListClass, damageDealtStatId);
        if (!local) return { NULL, NULL };

        damageDealtStatCached = env->NewGlobalRef(local);
        env->DeleteLocalRef(local);

        StatBase wrapper{ env, damageDealtStatCached };
        wrapper.setDeleteRef(false);
        return wrapper;
    }
};
