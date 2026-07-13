#pragma once

#include "../../primitive/JavaObject.h"
#include <string>

struct UUIDData {
    jint hashCode;

    UUIDData() : hashCode(0) {}
    UUIDData(jint hash) : hashCode(hash) {}

    bool equals(const UUIDData& other) const {
        return hashCode == other.hashCode;
    }
};

class JavaUUID : public JavaObject {
    struct Ids {
        jclass clazz;
        jmethodID equals;
        jmethodID hashCode;
    };
    static Ids ids;

    static void ensureInit(JNIEnv* env) {
        if (ids.clazz) return;
        jclass local = env->FindClass("java/util/UUID");
        if (!local) { env->ExceptionClear(); return; }
        ids.clazz    = static_cast<jclass>(env->NewGlobalRef(local));
        env->DeleteLocalRef(local);
        ids.equals   = env->GetMethodID(ids.clazz, "equals", "(Ljava/lang/Object;)Z");
        ids.hashCode = env->GetMethodID(ids.clazz, "hashCode", "()I");
    }

public:
    JavaUUID(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    bool equals(JavaObject& other) const {
        ensureInit(this->env);
        if (!ids.equals) return false;
        return this->env->CallBooleanMethod(this->obj, ids.equals, other.getObj());
    }

    jint getHashCode() const {
        ensureInit(this->env);
        if (!ids.hashCode) return 0;
        return this->env->CallIntMethod(this->obj, ids.hashCode);
    }

    UUIDData toUUIDData() const {
        return { getHashCode() };
    }
};
