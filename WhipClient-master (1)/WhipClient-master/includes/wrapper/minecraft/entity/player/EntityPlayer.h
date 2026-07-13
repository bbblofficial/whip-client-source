#ifndef ENTITYPLAYER_H_
#define ENTITYPLAYER_H_

#include "../EntityLivingBase.h"
#include "inventoryplayer.h"
#include "../../inventory/Container.h"
#include "../../stats/StatBase.h"
#include "../../stats/Achievement.h"
#include "../../potion/Potion.h"
#include "../../../../../includes/wrapper/mojang/authlib/GameProfile.h"

class ItemStack;

class EntityPlayer : public EntityLivingBase {
	static jfieldID inventoryPlayerId;
	static jfieldID openContainerId;
	static jfieldID inventoryContainerId;
	static jmethodID currentEquippedItemId;
	static jmethodID closeScreenId;
	static jmethodID isUsingItemId;
	static jmethodID attackTargetEntityWithCurrentItemId;
	static jmethodID getHeldItemId;
	static jmethodID triggerAchievementId;
	static jmethodID setLastAttackerId;
	static jmethodID onEnchantmentCriticalId;
	static jmethodID onCriticalHitId;
	static jmethodID isPotionActiveId;
	static jmethodID isOnLadderId;
	static jmethodID isInWaterId;

	static jmethodID destroyCurrentEquippedItemId;
	static jmethodID addStatId;
	static jmethodID addExhaustionId;
	static jfieldID gameProfileId;
	static jmethodID isAllowEditId;
	static jmethodID jump;
	static jfieldID jumpTicksId;
	static jfieldID itemInUseCountId;

public:
	EntityPlayer(JNIEnv* env, jobject obj) : EntityLivingBase(env, obj) {}

	~EntityPlayer() {
		if (env && obj && deleteRef) {
			if (isGlobalRef) {
				env->DeleteGlobalRef(obj);
			} else {
				env->DeleteLocalRef(obj);
			}
		}
	}

	int JumpTicks() const {
		if (!jumpTicksId) jumpTicksId = mappings->getField("EntityLivingBase#jumpTicks");
		env->GetIntField(obj, jumpTicksId);
	}

	void JumpTicks(int val) const {
		if (!jumpTicksId) jumpTicksId = mappings->getField("EntityLivingBase#jumpTicks");
		env->SetIntField(obj, jumpTicksId, val);
	}

	ItemStack getCurrentEquippedItem();
	ItemStack getHeldItem();

	InventoryPlayer inventoryPlayer() {
		if (!inventoryPlayerId) inventoryPlayerId = mappings->getField("EntityPlayer#inventory");

		jobject obj = this->env->GetObjectField(this->obj, inventoryPlayerId);
		if (!obj) return { this->env, nullptr };

		return { this->env, obj };
	}

	Container inventoryContainer() {
		if (!inventoryContainerId) inventoryContainerId = mappings->getField("EntityPlayer#inventoryContainer");

		jobject obj = this->env->GetObjectField(this->obj, inventoryContainerId);
		if (!obj) return Container(this->env, NULL);

		return Container(this->env, obj);
	}

	Container openContainer() {
		if (!openContainerId) openContainerId = mappings->getField("EntityPlayer#openContainer");

		jobject obj = this->env->GetObjectField(this->obj, openContainerId);
		if (!obj) return Container(this->env, NULL);

		return Container(this->env, obj);
	}

	GameProfile gameProfile() {
		if (!gameProfileId) gameProfileId = mappings->getField("EntityPlayer#gameProfile");

		jobject obj = this->env->GetObjectField(this->obj, gameProfileId);
		if (!obj) return GameProfile(this->env, NULL);

		return GameProfile(this->env, obj);
	}

	bool attackTargetEntityWithCurrentItem(jobject targetEntity) {
		if (!attackTargetEntityWithCurrentItemId)
			attackTargetEntityWithCurrentItemId = mappings->getMethod("EntityPlayer#attackTargetEntityWithCurrentItem");

		if (this->obj != nullptr) {
			this->env->CallVoidMethod(this->obj, attackTargetEntityWithCurrentItemId, targetEntity);
			return true;
		}

		return false;
	}

	void triggerAchievement(Achievement achievement) {
		if (!triggerAchievementId) triggerAchievementId = mappings->getMethod("EntityPlayer#triggerAchievement");
		this->env->CallVoidMethod(this->obj, triggerAchievementId, achievement.getObj());
	}

	void setLastAttacker(Entity entity) {
		if (!setLastAttackerId) setLastAttackerId = mappings->getMethod("EntityLivingBase#setLastAttacker");
		this->env->CallVoidMethod(this->obj, setLastAttackerId, entity.getObj());
	}

	void onEnchantmentCritical(Entity entity) {
		if (!onEnchantmentCriticalId) onEnchantmentCriticalId = mappings->getMethod("EntityPlayer#onEnchantmentCritical");
		this->env->CallVoidMethod(this->obj, onEnchantmentCriticalId, entity.getObj());
	}

	void onCriticalHit(Entity entity) {
		if (!onCriticalHitId) onCriticalHitId = mappings->getMethod("EntityPlayer#onCriticalHit");
		this->env->CallVoidMethod(this->obj, onCriticalHitId, entity.getObj());
	}

	bool isPotionActive(Potion potion) {
		if (!isPotionActiveId) isPotionActiveId = mappings->getMethod("EntityLivingBase#isPotionActive");
		return this->env->CallBooleanMethod(this->obj, isPotionActiveId, potion.getObj());
	}

	bool isOnLadder() {
		if (!isOnLadderId) isOnLadderId = mappings->getMethod("EntityLivingBase#isOnLadder");
		return this->env->CallBooleanMethod(this->obj, isOnLadderId);
	}

	bool isInWater() {
		if (!isInWaterId) isInWaterId = mappings->getMethod("Entity#isInWater");
		return this->env->CallBooleanMethod(this->obj, isInWaterId);
	}

	bool setJump() {
		if (!jump) jump = mappings->getMethod("EntityPlayer#jump");
		return this->env->CallBooleanMethod(this->obj, jump);
	}

	bool isAllowEdit() {
		if (!isAllowEditId) isAllowEditId = mappings->getMethod("EntityPlayer#isAllowEdit");
		return this->env->CallBooleanMethod(this->obj, isAllowEditId);
	}

	void destroyCurrentEquippedItem() {
		if (!destroyCurrentEquippedItemId) destroyCurrentEquippedItemId = mappings->getMethod("EntityPlayer#destroyCurrentEquippedItem");
		this->env->CallVoidMethod(this->obj, destroyCurrentEquippedItemId);
	}

	void addStat(StatBase stat, int amount) {
		if (!addStatId) addStatId = mappings->getMethod("EntityPlayer#addStat");
		this->env->CallVoidMethod(this->obj, addStatId, stat.getObj(), amount);
	}

	void addExhaustion(float exhaustion) {
		if (!addExhaustionId) addExhaustionId = mappings->getMethod("EntityPlayer#addExhaustion");
		this->env->CallVoidMethod(this->obj, addExhaustionId, exhaustion);
	}

	void closeScreen() const {
		if (!closeScreenId) closeScreenId = mappings->getMethod("EntityPlayer#closeScreen");

		this->env->CallVoidMethod(this->obj, closeScreenId);
	}

	bool hasWeaponInHand();
	bool hasConsumableInHand();
	bool hasHealInHand();
	bool hasBlock();
	bool hasFullHotbar();
	bool hasEnderPearl();

	bool isUsingItem() {
		if (!isUsingItemId) isUsingItemId = mappings->getMethod("EntityPlayer#isUsingItem");

		return this->env->CallBooleanMethod(this->obj, isUsingItemId);
	}

	int itemInUseCount() {
		if (!itemInUseCountId) itemInUseCountId = mappings->getField("EntityPlayer#itemInUseCount");
		if (!itemInUseCountId) return 0;
		int v = this->env->GetIntField(this->obj, itemInUseCountId);
		if (this->env->ExceptionCheck()) { this->env->ExceptionClear(); return 0; }
		return v;
	}
};

#endif
