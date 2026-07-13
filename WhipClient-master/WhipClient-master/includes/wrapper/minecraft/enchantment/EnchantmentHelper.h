#ifndef ENCHANTMENTHELPER_H_
#define ENCHANTMENTHELPER_H_

#include "../../../../includes/wrapper/primitive/JavaObject.h"

class ItemStack;
class EnumCreatureAttribute;
class EntityLivingBase;
class Entity;

class EnchantmentHelper : public JavaObject {
private:
    static jclass enchantmentHelperClass;
    static jmethodID getModifierForCreatureId;
    static jmethodID getKnockbackModifierId;
    static jmethodID getFireAspectModifierId;
    static jmethodID applyThornEnchantmentsId;
    static jmethodID applyArthropodEnchantmentsId;
    static jmethodID func_151384_aId;
    static jmethodID func_151385_bId;
    static jmethodID getEnchantmentModifierLivingId;
    static jmethodID getEnchantmentLevelId;

public:
    EnchantmentHelper(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    static float getModifierForCreature(JNIEnv* env, ItemStack itemStack, EnumCreatureAttribute creatureAttribute);
    static int getKnockbackModifier(JNIEnv* env, EntityLivingBase entity);
    static int getFireAspectModifier(JNIEnv* env, EntityLivingBase entity);
    static void applyThornEnchantments(JNIEnv* env, EntityLivingBase target, Entity attacker);
    static void applyArthropodEnchantments(JNIEnv* env, Entity user, Entity target);
    static void func_151384_a(JNIEnv* env, EntityLivingBase entity, Entity target);
    static void func_151385_b(JNIEnv* env, EntityLivingBase entity, Entity target);
    static float getEnchantmentModifierLiving(JNIEnv* env, EntityLivingBase attacker, EntityLivingBase target);
    static int getEnchantmentLevel(JNIEnv* env, int enchantmentId, jobject itemStack);
};

#endif
