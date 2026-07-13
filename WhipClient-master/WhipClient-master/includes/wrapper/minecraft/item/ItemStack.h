#ifndef ITEMSTACK_H_
#define ITEMSTACK_H_
#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "Item.h"

class EntityPlayer;
class EntityLivingBase;
class Block;

class ItemStack : public JavaObject {
private:
	static jfieldID theItemId;
	static jfieldID metadataId;
	static jfieldID stackSizeId;
	static jmethodID hitEntityId;
	static jmethodID canDestroyId;
	static jmethodID getStrVsBlockId;
	static jmethodID getDisplayNameId;

public:
	ItemStack(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

	Item theItem() {
		if (!theItemId) theItemId = mappings->getField("ItemStack#item");
		if (!theItemId) return { this->env, nullptr };
		jobject obj = this->env->GetObjectField(this->obj, theItemId);
		if (!obj) return { this->env, nullptr };

		return { this->env, obj };
	}

	jstring getDisplayName() {
		if (!getDisplayNameId) getDisplayNameId = mappings->getMethod("ItemStack#getDisplayName");
		if (!getDisplayNameId) return nullptr;
		jobject obj = this->env->CallObjectMethod(this->obj, getDisplayNameId);
		if (this->env->ExceptionCheck()) {
			this->env->ExceptionClear();
			return nullptr;
		}
		return static_cast<jstring>(obj);
	}

	bool hitEntity(EntityLivingBase entity, EntityPlayer player);
	bool canDestroy(Block block);

	int getStackSize() {
		if (!stackSizeId) stackSizeId = mappings->getField("ItemStack#stackSize");
		return this->env->GetIntField(this->obj, stackSizeId);
	}

	bool isWeapon() {
		Item item = this->theItem();
		if (item.isNull()) return false;

		return item.isWeapon();
	}

	bool isConsumable() {
		Item item = this->theItem();
		if (item.isNull()) return false;

		return item.isConsumable();
	}

	bool isHeal() {
		int itemDamage = this->metadata();
		return itemDamage == 16421 || itemDamage == 16453;
	}

	bool isSoup() {
		Item item = this->theItem();
		if (item.isNull()) return false;
		return item.isSoup();
	}

	bool isPunch() {
		Item item = this->theItem();
		if (item.isNull()) return false;
		return item.isBow();
	}

	bool IsPearl() {
		Item item = this->theItem();
		if (item.isNull()) return false;
		return item.isEnderPearl();
	}

	bool isRod() {
		Item item = this->theItem();
		if (item.isNull()) return false;
		return item.isFishingRod();
	}

	bool isFood() {
		Item item = this->theItem();
		if (item.isNull()) return false;
		return item.isFood();
	}

	bool isPotion() {
		Item item = this->theItem();
		if (item.isNull()) return false;
		return item.isPotion();
	}

	bool isBlock() {
		Item item = this->theItem();
		if (item.isNull()) return false;

		return item.isBlock();
	}

	bool isSword() {
		Item item = this->theItem();
		if (item.isNull()) return false;
		return item.isSword();
	}

	int metadata() {
		if (!metadataId) metadataId = mappings->getField("ItemStack#itemDamage");
		return this->env->GetIntField(this->obj, metadataId);
	}

	int getItemId() {
		Item item = this->theItem();
		if (item.isNull()) return -1;
		return item.getId();
	}

	bool isWaterBucket() {
		Item item = this->theItem();
		return !item.isNull() && item.isWaterBucket();
	}

	bool isGoldenApple() {
		Item item = this->theItem();
		return !item.isNull() && item.isGoldenApple();
	}

	bool isSnowball() {
		Item item = this->theItem();
		return !item.isNull() && item.isSnowball();
	}

	bool isEgg() {
		Item item = this->theItem();
		return !item.isNull() && item.isEgg();
	}

	bool isProjectile() {
		Item item = this->theItem();
		return !item.isNull() && item.isProjectile();
	}

	bool isItemEnchanted() {
		static jmethodID isItemEnchantedId = nullptr;
		if (!isItemEnchantedId) isItemEnchantedId = mappings->getMethod("ItemStack#isItemEnchanted");
		if (!isItemEnchantedId) return false;
		return this->env->CallBooleanMethod(this->obj, isItemEnchantedId);
	}

	bool hasEffect() {
		static jmethodID hasEffectId = nullptr;
		if (!hasEffectId) hasEffectId = mappings->getMethod("ItemStack#hasEffect");
		if (!hasEffectId) return false;
		return this->env->CallBooleanMethod(this->obj, hasEffectId);
	}

	bool isArmor() {
		Item item = this->theItem();
		if (item.isNull()) return false;
		int id = item.getId();
		return (id >= 298 && id <= 317);
	}

	float getStrVsBlock(jobject block) {
		if (!getStrVsBlockId) getStrVsBlockId = mappings->getMethod("ItemStack#getStrVsBlock");
		if (!getStrVsBlockId) return 1.0f;

		jfloat result = this->env->CallFloatMethod(this->obj, getStrVsBlockId, block);
		if (this->env->ExceptionCheck()) {
			this->env->ExceptionClear();
			return 1.0f;
		}

		return static_cast<float>(result);
	}
};

#endif
