#include "../../../../includes/wrapper/minecraft/enchantment/EnchantmentHelper.h"
#include "../../../../includes/wrapper/minecraft/item/ItemStack.h"
#include "../../../../includes/wrapper/minecraft/entity/EnumCreatureAttribute.h"
#include "../../../../includes/wrapper/minecraft/entity/EntityLivingBase.h"
#include "../../../../includes/wrapper/minecraft/entity/Entity.h"

jclass EnchantmentHelper::enchantmentHelperClass = NULL;
jmethodID EnchantmentHelper::getModifierForCreatureId = NULL;
jmethodID EnchantmentHelper::getKnockbackModifierId = NULL;
jmethodID EnchantmentHelper::getFireAspectModifierId = NULL;
jmethodID EnchantmentHelper::applyThornEnchantmentsId = NULL;
jmethodID EnchantmentHelper::applyArthropodEnchantmentsId = NULL;
jmethodID EnchantmentHelper::func_151384_aId = NULL;
jmethodID EnchantmentHelper::func_151385_bId = NULL;
jmethodID EnchantmentHelper::getEnchantmentModifierLivingId = NULL;
jmethodID EnchantmentHelper::getEnchantmentLevelId = NULL;

float EnchantmentHelper::getModifierForCreature(JNIEnv* env, ItemStack itemStack, EnumCreatureAttribute creatureAttribute) {
    if (!enchantmentHelperClass) enchantmentHelperClass = mappings->getClass("EnchantmentHelper");
    if (!getModifierForCreatureId) getModifierForCreatureId = mappings->getMethod("EnchantmentHelper#getModifierForCreature");

    if (!env || !itemStack.getObj() || !creatureAttribute.getObj()) return 0.0f;

    return env->CallStaticFloatMethod(
        enchantmentHelperClass,
        getModifierForCreatureId,
        itemStack.getObj(),
        creatureAttribute.getObj()
    );
}

int EnchantmentHelper::getKnockbackModifier(JNIEnv* env, EntityLivingBase entity) {
    if (!enchantmentHelperClass) enchantmentHelperClass = mappings->getClass("EnchantmentHelper");
    if (!getKnockbackModifierId) getKnockbackModifierId = mappings->getMethod("EnchantmentHelper#getKnockbackModifier");

    if (!env || !entity.getObj()) return 0;

    return env->CallStaticIntMethod(
        enchantmentHelperClass,
        getKnockbackModifierId,
        entity.getObj()
    );
}

int EnchantmentHelper::getFireAspectModifier(JNIEnv* env, EntityLivingBase entity) {
    if (!enchantmentHelperClass) enchantmentHelperClass = mappings->getClass("EnchantmentHelper");
    if (!getFireAspectModifierId) getFireAspectModifierId = mappings->getMethod("EnchantmentHelper#getFireAspectModifier");

    if (!env || !entity.getObj()) return 0;

    return env->CallStaticIntMethod(
        enchantmentHelperClass,
        getFireAspectModifierId,
        entity.getObj()
    );
}

void EnchantmentHelper::applyThornEnchantments(JNIEnv* env, EntityLivingBase target, Entity attacker) {
    if (!enchantmentHelperClass) enchantmentHelperClass = mappings->getClass("EnchantmentHelper");
    if (!applyThornEnchantmentsId) applyThornEnchantmentsId = mappings->getMethod("EnchantmentHelper#applyThornEnchantments");

    if (!env || !target.getObj() || !attacker.getObj()) return;

    env->CallStaticVoidMethod(
        enchantmentHelperClass,
        applyThornEnchantmentsId,
        target.getObj(),
        attacker.getObj()
    );
}

void EnchantmentHelper::applyArthropodEnchantments(JNIEnv* env, Entity user, Entity target) {
    if (!enchantmentHelperClass) enchantmentHelperClass = mappings->getClass("EnchantmentHelper");
    if (!applyArthropodEnchantmentsId) applyArthropodEnchantmentsId = mappings->getMethod("EnchantmentHelper#applyArthropodEnchantments");

    if (!env || !user.getObj() || !target.getObj()) return;

    env->CallStaticVoidMethod(
        enchantmentHelperClass,
        applyArthropodEnchantmentsId,
        user.getObj(),
        target.getObj()
    );
}

void EnchantmentHelper::func_151384_a(JNIEnv* env, EntityLivingBase entity, Entity target) {
    if (!enchantmentHelperClass) enchantmentHelperClass = mappings->getClass("EnchantmentHelper");
    if (!func_151384_aId) func_151384_aId = mappings->getMethod("EnchantmentHelper#applyThornEnchantments");

    if (!env || !entity.getObj() || !target.getObj()) return;

    env->CallStaticVoidMethod(
        enchantmentHelperClass,
        func_151384_aId,
        entity.getObj(),
        target.getObj()
    );
}

void EnchantmentHelper::func_151385_b(JNIEnv* env, EntityLivingBase entity, Entity target) {
    if (!enchantmentHelperClass) enchantmentHelperClass = mappings->getClass("EnchantmentHelper");
    if (!func_151385_bId) func_151385_bId = mappings->getMethod("EnchantmentHelper#applyArthropodEnchantments");

    if (!env || !entity.getObj() || !target.getObj()) return;

    env->CallStaticVoidMethod(
        enchantmentHelperClass,
        func_151385_bId,
        entity.getObj(),
        target.getObj()
    );
}

float EnchantmentHelper::getEnchantmentModifierLiving(JNIEnv* env, EntityLivingBase attacker, EntityLivingBase target) {
    if (!enchantmentHelperClass) enchantmentHelperClass = mappings->getClass("EnchantmentHelper");
    if (!getEnchantmentModifierLivingId) getEnchantmentModifierLivingId = mappings->getMethod("EnchantmentHelper#getEnchantmentModifierLiving");

    if (!env || !attacker.getObj() || !target.getObj()) return 0.0f;

    return env->CallStaticFloatMethod(
        enchantmentHelperClass,
        getEnchantmentModifierLivingId,
        attacker.getObj(),
        target.getObj()
    );
}

int EnchantmentHelper::getEnchantmentLevel(JNIEnv* env, int enchantmentId, jobject itemStack) {
    if (!enchantmentHelperClass) enchantmentHelperClass = mappings->getClass("EnchantmentHelper");
    if (!getEnchantmentLevelId) getEnchantmentLevelId = mappings->getMethod("EnchantmentHelper#getEnchantmentLevel");

    if (!env || !itemStack || !getEnchantmentLevelId) return 0;

    return env->CallStaticIntMethod(
        enchantmentHelperClass,
        getEnchantmentLevelId,
        enchantmentId,
        itemStack
    );
}
