#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"

class EnumCreatureAttribute : public JavaObject {
private:
    static jfieldID arthropodID;
    static jfieldID undeadID;
    static jfieldID undefinedID;
    static jclass enumCreatureAttributeClass;
    static jobject arthropodCached;
    static jobject undeadCached;
    static jobject undefinedCached;

public:
    EnumCreatureAttribute(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    static EnumCreatureAttribute ARTHROPOD(JNIEnv* env) {
        if (!env) return { NULL, NULL };

        if (arthropodCached) {
            EnumCreatureAttribute wrapper{ env, arthropodCached };
            wrapper.setDeleteRef(false);
            return wrapper;
        }

        if (!enumCreatureAttributeClass) enumCreatureAttributeClass = mappings->getClass("EnumCreatureAttribute");
        if (!arthropodID) arthropodID = mappings->getField("EnumCreatureAttribute#ARTHROPOD");

        jobject local = env->GetStaticObjectField(enumCreatureAttributeClass, arthropodID);
        if (!local) return { NULL, NULL };

        arthropodCached = env->NewGlobalRef(local);
        env->DeleteLocalRef(local);

        EnumCreatureAttribute wrapper{ env, arthropodCached };
        wrapper.setDeleteRef(false);
        return wrapper;
    }

    static EnumCreatureAttribute UNDEAD(JNIEnv* env) {
        if (!env) return { NULL, NULL };

        if (undeadCached) {
            EnumCreatureAttribute wrapper{ env, undeadCached };
            wrapper.setDeleteRef(false);
            return wrapper;
        }

        if (!enumCreatureAttributeClass) enumCreatureAttributeClass = mappings->getClass("EnumCreatureAttribute");
        if (!undeadID) undeadID = mappings->getField("EnumCreatureAttribute#UNDEAD");

        jobject local = env->GetStaticObjectField(enumCreatureAttributeClass, undeadID);
        if (!local) return { NULL, NULL };

        undeadCached = env->NewGlobalRef(local);
        env->DeleteLocalRef(local);

        EnumCreatureAttribute wrapper{ env, undeadCached };
        wrapper.setDeleteRef(false);
        return wrapper;
    }

    static EnumCreatureAttribute UNDEFINED(JNIEnv* env) {
        if (!env) return { NULL, NULL };

        if (undefinedCached) {
            EnumCreatureAttribute wrapper{ env, undefinedCached };
            wrapper.setDeleteRef(false);
            return wrapper;
        }

        if (!enumCreatureAttributeClass) enumCreatureAttributeClass = mappings->getClass("EnumCreatureAttribute");
        if (!undefinedID) undefinedID = mappings->getField("EnumCreatureAttribute#UNDEFINED");

        jobject local = env->GetStaticObjectField(enumCreatureAttributeClass, undefinedID);
        if (!local) return { NULL, NULL };

        undefinedCached = env->NewGlobalRef(local);
        env->DeleteLocalRef(local);

        EnumCreatureAttribute wrapper{ env, undefinedCached };
        wrapper.setDeleteRef(false);
        return wrapper;
    }
};
