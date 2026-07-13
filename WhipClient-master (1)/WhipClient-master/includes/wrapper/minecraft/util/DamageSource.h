#ifndef DAMAGESOURCE_H_
#define DAMAGESOURCE_H_

#include "../../../../includes/wrapper/primitive/javaobject.h"

class EntityPlayer;

class DamageSource : public JavaObject {
private:
    static jclass damageSourceClass;
    static jmethodID causePlayerDamageId;

public:
    DamageSource(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    static DamageSource causePlayerDamage(JNIEnv* env, EntityPlayer player);
};

#endif
