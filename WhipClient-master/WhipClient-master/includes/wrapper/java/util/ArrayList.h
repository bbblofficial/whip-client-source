#pragma once

#include "../../primitive/JavaObject.h"

class ArrayList : public JavaObject {
    struct Ids {
        jclass clazz;
        jmethodID init;
        jmethodID initCapacity;
        jmethodID size;
        jmethodID get;
        jmethodID remove;
        jmethodID add;
        jmethodID isEmpty;
    };
    static Ids ids;

    static void ensureInit(JNIEnv* env) {
        if (ids.clazz) return;
        jclass local = env->FindClass("java/util/ArrayList");
        if (!local) { env->ExceptionClear(); return; }
        ids.clazz = static_cast<jclass>(env->NewGlobalRef(local));
        env->DeleteLocalRef(local);
        ids.init         = env->GetMethodID(ids.clazz, "<init>", "()V");
        ids.initCapacity = env->GetMethodID(ids.clazz, "<init>", "(I)V");
        ids.size         = env->GetMethodID(ids.clazz, "size", "()I");
        ids.get          = env->GetMethodID(ids.clazz, "get", "(I)Ljava/lang/Object;");
        ids.remove       = env->GetMethodID(ids.clazz, "remove", "(Ljava/lang/Object;)Z");
        ids.add          = env->GetMethodID(ids.clazz, "add", "(Ljava/lang/Object;)Z");
        ids.isEmpty      = env->GetMethodID(ids.clazz, "isEmpty", "()Z");
    }

public:
    ArrayList(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    static ArrayList create(JNIEnv* env) {
        ensureInit(env);
        if (!ids.clazz || !ids.init) return { env, nullptr };
        return { env, env->NewObject(ids.clazz, ids.init) };
    }

    static ArrayList createWithCapacity(JNIEnv* env, int capacity) {
        ensureInit(env);
        if (!ids.clazz || !ids.initCapacity) return { env, nullptr };
        return { env, env->NewObject(ids.clazz, ids.initCapacity, capacity) };
    }

    int size() const {
        ensureInit(this->env);
        if (!ids.size) return 0;
        return this->env->CallIntMethod(this->obj, ids.size);
    }

    JavaObject get(int index) const {
        ensureInit(this->env);
        if (!ids.get) return { NULL, NULL };
        jobject obj = this->env->CallObjectMethod(this->obj, ids.get, index);
        if (!obj) return { NULL, NULL };
        return { this->env, obj };
    }

    bool remove(JavaObject& obj) {
        ensureInit(this->env);
        if (!ids.remove) return false;
        return this->env->CallBooleanMethod(this->obj, ids.remove, obj.getObj());
    }

    bool add(JavaObject& obj) {
        ensureInit(this->env);
        if (!ids.add) return false;
        return this->env->CallBooleanMethod(this->obj, ids.add, obj.getObj());
    }

    bool isEmpty() {
        ensureInit(this->env);
        if (!ids.isEmpty) return true;
        return this->env->CallBooleanMethod(this->obj, ids.isEmpty);
    }
};
