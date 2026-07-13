#include "../../../../includes/wrapper/minecraft/util/DamageSource.h"
#include "../../../../includes/wrapper/minecraft/entity/player/EntityPlayer.h"

jclass DamageSource::damageSourceClass = NULL;
jmethodID DamageSource::causePlayerDamageId = NULL;

DamageSource DamageSource::causePlayerDamage(JNIEnv* env, EntityPlayer player) {
    if (!damageSourceClass) damageSourceClass = mappings->getClass("DamageSource");
    if (!causePlayerDamageId) causePlayerDamageId = mappings->getMethod("DamageSource#causePlayerDamage");

    jobject obj = env->CallStaticObjectMethod(damageSourceClass, causePlayerDamageId, player.getObj());
    if (!obj) return DamageSource(NULL, NULL);
    return DamageSource(env, obj);
}
