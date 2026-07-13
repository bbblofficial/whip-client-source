#include "../../../../../includes/wrapper/minecraft/entity/player/EntityPlayer.h"
#include "../../../../../includes/wrapper/minecraft/item/ItemStack.h"

jfieldID EntityPlayer::inventoryPlayerId = NULL;
jfieldID EntityPlayer::openContainerId = NULL;
jfieldID EntityPlayer::inventoryContainerId = NULL;
jmethodID EntityPlayer::currentEquippedItemId = NULL;
jmethodID EntityPlayer::closeScreenId = NULL;
jmethodID EntityPlayer::isUsingItemId = NULL;
jmethodID EntityPlayer::attackTargetEntityWithCurrentItemId = NULL;
jmethodID EntityPlayer::getHeldItemId = NULL;
jmethodID EntityPlayer::triggerAchievementId = NULL;
jmethodID EntityPlayer::setLastAttackerId = NULL;
jmethodID EntityPlayer::onEnchantmentCriticalId = NULL;
jmethodID EntityPlayer::onCriticalHitId = NULL;
jmethodID EntityPlayer::isPotionActiveId = NULL;
jmethodID EntityPlayer::isOnLadderId = NULL;
jmethodID EntityPlayer::isInWaterId = NULL;
jmethodID EntityPlayer::destroyCurrentEquippedItemId = NULL;
jmethodID EntityPlayer::addStatId = NULL;
jmethodID EntityPlayer::addExhaustionId = NULL;
jfieldID EntityPlayer::gameProfileId = NULL;
jmethodID EntityPlayer::isAllowEditId = NULL;
jfieldID EntityPlayer::jumpTicksId = NULL;
jmethodID EntityPlayer::jump = NULL;
jfieldID EntityPlayer::itemInUseCountId = NULL;

ItemStack EntityPlayer::getCurrentEquippedItem() {
	if (!currentEquippedItemId) currentEquippedItemId = mappings->getMethod("EntityPlayer#getCurrentEquippedItem");
	const auto obj = this->env->CallObjectMethod(this->obj, currentEquippedItemId);
	if (!obj) {
		return { env, nullptr };
	}

	return { this->env, obj };
}

ItemStack EntityPlayer::getHeldItem() {
	if (!getHeldItemId) getHeldItemId = mappings->getMethod("EntityPlayer#getHeldItem");
	const auto obj = this->env->CallObjectMethod(this->obj, getHeldItemId);
	if (!obj) return { env, nullptr };

	return { this->env, obj };
}

bool EntityPlayer::hasWeaponInHand() {
	ItemStack currentEquippedItem = this->getCurrentEquippedItem();
	if (currentEquippedItem.isNull()) {
		return false;
	}
	return currentEquippedItem.isWeapon();
}

bool EntityPlayer::hasEnderPearl() {
	ItemStack currentEquippedItem = this->getCurrentEquippedItem();
	if (currentEquippedItem.isNull()) {
		return false;
	}
	return currentEquippedItem.IsPearl();
}

bool EntityPlayer::hasConsumableInHand() {
	ItemStack currentEquippedItem = this->getCurrentEquippedItem();
	if (currentEquippedItem.isNull())
		return false;
	return currentEquippedItem.isConsumable();
}

bool EntityPlayer::hasHealInHand() {
	ItemStack currentEquippedItem = this->getCurrentEquippedItem();
	if (currentEquippedItem.isNull())
		return false;
	return currentEquippedItem.isHeal();
}

bool EntityPlayer::hasBlock() {
	ItemStack currentEquippedItem = this->getCurrentEquippedItem();
	if (currentEquippedItem.isNull())
		return false;

	return currentEquippedItem.isBlock();
}

bool EntityPlayer::hasFullHotbar() {
	InventoryPlayer inventoryPlayer = this->inventoryPlayer();
	if (inventoryPlayer.isNull())
		return false;
	return inventoryPlayer.isHotbarFull();
}
