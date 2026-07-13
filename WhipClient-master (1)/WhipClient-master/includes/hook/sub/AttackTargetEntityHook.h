#pragma once

#include "../includes/hook/base/BaseHook.h"
#include "../includes/bus/EventBus.h"
#include "../includes/event/sub/AttackEntityEvent.h"
#include "../includes/event/sub/PlayerAttackEvent.h"
#include "includes/wrapper/minecraft/entity/SharedMonsterAttributes.h"
#include "includes/wrapper/minecraft/entity/EnumCreatureAttribute.h"
#include "includes/wrapper/minecraft/enchantment/EnchantmentHelper.h"
#include "includes/wrapper/minecraft/util/DamageSource.h"
#include "includes/wrapper/minecraft/potion/potion.h"
#include "includes/wrapper/minecraft/entity/player/EntityPlayerMP.h"
#include "includes/wrapper/minecraft/stats/AchievementList.h"
#include "includes/wrapper/minecraft/entity/boss/EntityDragonPart.h"
#include "includes/wrapper/minecraft/stats/StatList.h"
#include "includes/wrapper/minecraft/util/MathHelper.h"
#include "includes/util/MathUtils.h"

class AttackTargetEntityHook final : public StaticBaseHook<AttackTargetEntityHook> {
    bool wasSprintingBeforeAttack = false;

public:
    AttackTargetEntityHook() : StaticBaseHook(HookPosition::PRE) {}

    ~AttackTargetEntityHook() override = default;

    static std::string getHookName() {
        return "EntityPlayer#attackTargetEntityWithCurrentItem";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        if (!env) {
            return HookResult::Continue();
        }

        jobject playerObj = getArg(env, args, 0);
        if (!playerObj) {
            return HookResult::Continue();
        }

        jobject entityObj = getArg(env, args, 1);
        if (!entityObj) {
            return HookResult::Continue();
        }

        EntityPlayer this_player(env, playerObj);
        this_player.setDeleteRef(false);
        Entity entity(env, entityObj);
        entity.setDeleteRef(false);

        PlayerAttackEvent playerAttackEvent(env, entity.entityId());
        EventBus::getInstance().dispatch(playerAttackEvent);

        if (playerAttackEvent.isCancelled()) {
            return HookResult::Cancel(env);
        }

        wasSprintingBeforeAttack = this_player.isSprinting();

        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {

            if (entity.canAttackWithItem())
            {
                if (!entity.hitByEntity(this_player))
                {

                    IAttribute attribute = SharedMonsterAttributes::AttackDamage(env);
                    attribute.setDeleteRef(false);

                    auto attackAttribute = this_player.getEntityAttribute(attribute, env);
                    attackAttribute.setDeleteRef(false);

                    double f = attackAttribute.getAttributeValue();

                    int i = 0;
                    float f1 = 0.0F;

                    if (entity.isInstanceOf("EntityLivingBase"))
                    {
                        EntityLivingBase livingBase = entity.convertTo<EntityLivingBase>();

                        auto heldItem = this_player.getHeldItem();
                        f1 = EnchantmentHelper::getModifierForCreature(env, heldItem, livingBase.getCreatureAttribute());
                    }
                    else
                    {
                        auto heldItem = this_player.getHeldItem();
                        f1 = EnchantmentHelper::getModifierForCreature(env, heldItem, EnumCreatureAttribute::UNDEFINED(env));
                    }

                    auto playerLivingBase = this_player.convertTo<EntityLivingBase>();

                    i = i + EnchantmentHelper::getKnockbackModifier(env, playerLivingBase);

                    if (this_player.isSprinting())
                    {
                        ++i;
                    }

                    if (f > 0.0F || f1 > 0.0F)
                    {
                        bool flag = this_player.getFallDistance() > 0.0F &&
                            !this_player.onGround() &&
                            !this_player.isOnLadder() &&
                            !this_player.isInWater() &&
                            !this_player.isPotionActive(Potion::blindness(env)) &&
                            entity.isInstanceOf("EntityLivingBase");

                        if (flag && f > 0.0F)
                        {
                            f *= 1.5F;
                        }

                        f = f + f1;

                        bool flag1 = false;
                        int j = EnchantmentHelper::getFireAspectModifier(env, playerLivingBase);

                        if (entity.isInstanceOf("EntityLivingBase") && j > 0 && !entity.isBurning())
                        {
                            flag1 = true;
                            entity.setFire(1);
                        }

                        bool flag2 = entity.attackEntityFrom(DamageSource::causePlayerDamage(env, this_player), f);

                        if (flag2)
                        {
                            if (i > 0)
                            {
                                this_player.setSprinting(false);

                                AttackEntityEvent event(env, 0.6f, entityObj);
                                EventBus::getInstance().dispatch(event);

                                if (event.isCancelled()) {
                                    return HookResult::Cancel(env);
                                }

                                const float retainedSpeed = event.getRetainedSpeed();
                                this_player.setMotionX(this_player.motionX() * retainedSpeed);
                                this_player.setMotionZ(this_player.motionZ() * retainedSpeed);

                                if (wasSprintingBeforeAttack && retainedSpeed != 0.6f) {
                                    this_player.setSprinting(true);
                                }

                                entity.addVelocity(
                                    -MathHelper::sin(env, this_player.rotationYaw() * (float)PI / 180.0F) * (float)i * 0.5F,
                                    0.1,
                                    MathHelper::cos(env, this_player.rotationYaw() * (float)PI / 180.0F) * (float)i * 0.5F
                                );
                            }

                            if (flag)
                            {
                                this_player.onCriticalHit(entity);
                            }

                            if (f1 > 0.0F)
                            {
                                this_player.onEnchantmentCritical(entity);
                            }

                            if (f >= 18.0F)
                            {
                                this_player.triggerAchievement(AchievementList::overkill(env));
                            }

                            this_player.setLastAttacker(entity);

                            if (entity.isInstanceOf("EntityLivingBase"))
                            {
                                EnchantmentHelper::applyThornEnchantments(env, entity.convertTo<EntityLivingBase>(), this_player);
                            }

                            EnchantmentHelper::applyArthropodEnchantments(env, this_player, entity);

                            ItemStack itemstack = this_player.getCurrentEquippedItem();
                            Entity targetEntity = entity;

                            if (entity.isInstanceOf("EntityDragonPart"))
                            {
                                EntityDragonPart dragonPart = entity.convertTo<EntityDragonPart>();
                                IEntityMultiPart ientitymultipart = dragonPart.getEntityDragonObj();

                                if (ientitymultipart.isInstanceOf("EntityLivingBase"))
                                {
                                    targetEntity = ientitymultipart.convertTo<EntityLivingBase>();
                                }
                            }

                            if (!itemstack.isNull() && targetEntity.isInstanceOf("EntityLivingBase"))
                            {
                                itemstack.hitEntity(targetEntity.convertTo<EntityLivingBase>(), this_player);

                                if (itemstack.getStackSize() <= 0)
                                {
                                    this_player.destroyCurrentEquippedItem();
                                }
                            }

                            if (entity.isInstanceOf("EntityLivingBase"))
                            {
                                this_player.addStat(StatList::damageDealtStat(env), round(f * 10.0F));

                                if (j > 0)
                                {
                                    entity.setFire(j * 4);
                                }
                            }

                            this_player.addExhaustion(0.3F);
                        }
                        else if (flag1)
                        {
                            entity.extinguish();
                        }
                    }
                }
            }
        }

        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {

            if (entity.canAttackWithItem())
            {
                if (!entity.hitByEntity(this_player))
                {
                    IAttribute attribute = SharedMonsterAttributes::AttackDamage(env);
                    attribute.setDeleteRef(false);

                    auto attackAttribute = this_player.getEntityAttribute(attribute, env);
                    attackAttribute.setDeleteRef(false);

                    float f = (float)attackAttribute.getAttributeValue();

                    int i = 0;
                    float f1 = 0.0F;

                    if (entity.isInstanceOf("EntityLivingBase"))
                    {
                        EntityLivingBase livingBase = entity.convertTo<EntityLivingBase>();

                        f1 = EnchantmentHelper::getEnchantmentModifierLiving(env, this_player, livingBase);
                        i += EnchantmentHelper::getKnockbackModifier(env, entity.convertTo<EntityLivingBase>());
                    }

                    if (this_player.isSprinting())
                    {
                        ++i;
                    }

                    if (f > 0.0F || f1 > 0.0F)
                    {
                        bool flag = this_player.getFallDistance() > 0.0F &&
                            !this_player.onGround() &&
                            !this_player.isOnLadder() &&
                            !this_player.isInWater() &&
                            !this_player.isPotionActive(Potion::blindness(env)) &&

                            entity.isInstanceOf("EntityLivingBase");

                        if (flag && f > 0.0F)
                        {
                            f *= 1.5F;
                        }

                        f += f1;
                        bool flag1 = false;
                        int j = EnchantmentHelper::getFireAspectModifier(env, this_player);

                        if (entity.isInstanceOf("EntityLivingBase") && j > 0 && !entity.isBurning())
                        {
                            flag1 = true;
                            entity.setFire(1);
                        }

                        bool flag2 = entity.attackEntityFrom(DamageSource::causePlayerDamage(env, this_player), f);

                        if (flag2)
                        {
                            if (i > 0)
                            {
                                this_player.setSprinting(false);

                                AttackEntityEvent event(env, 0.6f, entityObj);
                                EventBus::getInstance().dispatch(event);

                                if (event.isCancelled()) {
                                    return HookResult::Cancel(env);
                                }

                                const float retainedSpeed = event.getRetainedSpeed();
                                this_player.setMotionX(this_player.motionX() * retainedSpeed);
                                this_player.setMotionZ(this_player.motionZ() * retainedSpeed);

                                if (wasSprintingBeforeAttack && retainedSpeed != 0.6f) {
                                    this_player.setSprinting(true);
                                }

                                entity.addVelocity(
                                    -MathHelper::sin(env, this_player.rotationYaw() * (float)PI / 180.0F) * (float)i * 0.5F,
                                    0.1,
                                    MathHelper::cos(env, this_player.rotationYaw() * (float)PI / 180.0F) * (float)i * 0.5F
                                );
                            }

                            if (flag)
                            {
                                this_player.onCriticalHit(entity);
                            }

                            if (f1 > 0.0F)
                            {
                                this_player.onEnchantmentCritical(entity);
                            }

                            if (f >= 18.0F)
                            {
                                this_player.triggerAchievement(AchievementList::overkill(env));
                            }

                            this_player.setLastAttacker(entity);

                            if (entity.isInstanceOf("EntityLivingBase"))
                            {
                                EnchantmentHelper::func_151384_a(env, entity.convertTo<EntityLivingBase>(), this_player);
                            }

                            EnchantmentHelper::func_151385_b(env, this_player, entity);

                            ItemStack itemstack = this_player.getCurrentEquippedItem();
                            Entity targetEntity = entity;

                            if (entity.isInstanceOf("EntityDragonPart"))
                            {
                                EntityDragonPart dragonPart = entity.convertTo<EntityDragonPart>();
                                IEntityMultiPart ientitymultipart = dragonPart.getEntityDragonObj();

                                if (ientitymultipart.isInstanceOf("EntityLivingBase"))
                                {
                                    targetEntity = ientitymultipart.convertTo<Entity>();
                                }
                            }

                            if (!itemstack.isNull() && targetEntity.isInstanceOf("EntityLivingBase"))
                            {
                                itemstack.hitEntity(targetEntity.convertTo<EntityLivingBase>(), this_player);

                                if (itemstack.getStackSize() <= 0)
                                {
                                    this_player.destroyCurrentEquippedItem();
                                }
                            }

                            if (entity.isInstanceOf("EntityLivingBase"))
                            {
                                this_player.addStat(StatList::damageDealtStat(env), round(f * 10.0F));

                                if (j > 0)
                                {
                                    entity.setFire(j * 4);
                                }
                            }

                            this_player.addExhaustion(0.3F);
                        }
                        else if (flag1)
                        {
                            entity.extinguish();
                        }
                    }
                }
            }
        }

        return HookResult::Cancel(env);
    }
};
