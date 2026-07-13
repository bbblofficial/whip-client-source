#pragma once
#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../item/itemstack.h"
#include "../../entity/player/EntityPlayer.h"
#include "../../world/worldsettingsgametype.h"

class PlayerControllerMP : public JavaObject {
private:
	static jfieldID curBlockDamageMPId;
	static jfieldID blockHitDelayId;
	static jfieldID currentGameTypeId;
	static jmethodID windowClickId;
	static jmethodID isRidingHorseId;
	static jmethodID getBlockReachDistanceId;
	static jmethodID extendedReachId;
	static jmethodID onStoppedUsingItemId;
	static jmethodID clickBlockCreativeId;
	static jmethodID attackEntityId;
	static jmethodID onPlayerRightClickId;
public:
	PlayerControllerMP(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

	float curBlockDamageMP() {
		if (!curBlockDamageMPId) curBlockDamageMPId = mappings->getField("PlayerControllerMP#curBlockDamageMP");
		return this->env->GetFloatField(this->obj, curBlockDamageMPId);
	}

	float getBlockReachDistance() {
		if (!getBlockReachDistanceId) getBlockReachDistanceId = mappings->getMethod("PlayerControllerMP#getBlockReachDistance");
		return this->env->CallFloatMethod(this->obj, getBlockReachDistanceId);
	}

	void curBlockDamageMP(float v) {
		if (!curBlockDamageMPId) curBlockDamageMPId = mappings->getField("PlayerControllerMP#curBlockDamageMP");
		this->env->SetFloatField(this->obj, curBlockDamageMPId, v);
	}

	int blockHitDelay() {
		if (!blockHitDelayId) blockHitDelayId = mappings->getField("PlayerControllerMP#blockHitDelay");
		return this->env->GetIntField(this->obj, blockHitDelayId);
	}

	void blockHitDelay(int v) {
		if (!blockHitDelayId) blockHitDelayId = mappings->getField("PlayerControllerMP#blockHitDelay");
		this->env->SetIntField(this->obj, blockHitDelayId, v);
	}

	WorldSettingsGameType currentGameType() {
		if (!currentGameTypeId) currentGameTypeId = mappings->getField("PlayerControllerMP#currentGameType");
		jobject obj = this->env->GetObjectField(this->obj, currentGameTypeId);
		if (!obj) return { NULL, NULL };
		return { this->env, obj };
	}

	void currentGameType(jobject v) {
		if (!currentGameTypeId) currentGameTypeId = mappings->getField("PlayerControllerMP#currentGameType");
		this->env->SetObjectField(this->obj, currentGameTypeId, v);
	}

	bool extendedReach() {
		if (!extendedReachId) extendedReachId = mappings->getMethod("PlayerControllerMP#extendedReach");
		return this->env->CallBooleanMethod(this->obj, extendedReachId);
	}

	void onStoppedUsingItem(EntityPlayer playerIn) {
		if (!onStoppedUsingItemId) onStoppedUsingItemId = mappings->getMethod("PlayerControllerMP#onStoppedUsingItem");
		this->env->CallVoidMethod(this->obj, onStoppedUsingItemId, playerIn.getObj());
	}

	ItemStack windowClick(int windowId, int slot, int a, int b, EntityPlayer& thePlayer) {
		if (!windowClickId) windowClickId = mappings->getMethod("PlayerControllerMP#windowClick");

		jobject obj = this->env->CallObjectMethod(this->obj, windowClickId, windowId, slot, a, b, thePlayer.getObj());
		if (!obj) return { this->env, nullptr };
		return { this->env, obj };
	}

	bool isRidingHorse() {
		if (!isRidingHorseId) isRidingHorseId = mappings->getMethod("PlayerControllerMP#isRidingHorse");
		return this->env->CallBooleanMethod(this->obj, isRidingHorseId);
	}

	void clickBlockCreative(jobject minecraft, jobject playerController, jobject blockPos, jobject enumFacing) {
		if (!clickBlockCreativeId) clickBlockCreativeId = mappings->getMethod("PlayerControllerMP#clickBlockCreative");
		this->env->CallVoidMethod(this->obj, clickBlockCreativeId, minecraft, playerController, blockPos, enumFacing);
	}

	void attackEntity(EntityPlayer player, jobject targetEntity) {
		if (!attackEntityId) attackEntityId = mappings->getMethod("PlayerControllerMP#attackEntity");
		this->env->CallVoidMethod(this->obj, attackEntityId, player.getObj(), targetEntity);
	}

	bool onPlayerRightClick(jobject player, jobject world, jobject heldItem,
	                        jobject blockPos, jobject enumFacing, jobject hitVec) {
		if (!onPlayerRightClickId) onPlayerRightClickId = mappings->getMethod("PlayerControllerMP#onPlayerRightClick");
		if (!onPlayerRightClickId) return false;
		return this->env->CallBooleanMethod(this->obj, onPlayerRightClickId,
			player, world, heldItem, blockPos, enumFacing, hitVec);
	}
};
