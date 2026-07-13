#pragma once
#include "../../../../includes/wrapper/primitive/javaobject.h"
#include "Achievement.h"

class AchievementList : public JavaObject {
private:
    static jclass achievementListClass;
    static jfieldID overkillId;
    static jobject overkillCached;

public:
    AchievementList(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    static Achievement overkill(JNIEnv* env) {
        if (!env) return { NULL, NULL };

        if (overkillCached) {
            Achievement wrapper{ env, overkillCached };
            wrapper.setDeleteRef(false);
            return wrapper;
        }

        if (!achievementListClass) achievementListClass = mappings->getClass("AchievementList");
        if (!overkillId) overkillId = mappings->getField("AchievementList#overkill");

        jobject local = env->GetStaticObjectField(achievementListClass, overkillId);
        if (!local) return { NULL, NULL };

        overkillCached = env->NewGlobalRef(local);
        env->DeleteLocalRef(local);

        Achievement wrapper{ env, overkillCached };
        wrapper.setDeleteRef(false);
        return wrapper;
    }
};
