#pragma once

#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include <string>
#include <cctype>

class Item : public JavaObject {
	static jclass itemSwordClass;
	static jclass itemBowClass;
	static jclass itemPotionClass;
	static jclass itemFoodClass;
	static jclass itemAxeClass;
	static jclass itemSoupClass;
	static jclass itemBlockClass;
	static jclass itemArmorClass;
	static jclass itemRodClass;
	static jclass itemPearlClass;
	static bool selectedWeapons[3];
	static jclass itemBaseClass;
	static jmethodID getIdFromItemId;
	static jmethodID getUnlocalizedNameId;

public:
	Item(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

	static int getIdFromItem(JNIEnv* env, jobject itemObj) {
		if (!itemObj) return -1;
		if (!itemBaseClass) itemBaseClass = mappings->getClass("Item");
		if (!getIdFromItemId) getIdFromItemId = mappings->getMethod("Item#getIdFromItem");
		if (!itemBaseClass || !getIdFromItemId) return -1;
		return env->CallStaticIntMethod(itemBaseClass, getIdFromItemId, itemObj);
	}

	int getId() {
		return getIdFromItem(this->env, this->obj);
	}

	jstring getUnlocalizedName() {
		if (!getUnlocalizedNameId) getUnlocalizedNameId = mappings->getMethod("Item#getUnlocalizedName");
		if (!getUnlocalizedNameId) return nullptr;
		return (jstring)this->env->CallObjectMethod(this->obj, getUnlocalizedNameId);
	}

	static void updateWeaponSelections(const bool sword, const bool axe, const bool bow) {
		selectedWeapons[0] = sword;
		selectedWeapons[1] = axe;
		selectedWeapons[2] = bow;
	}

	bool isWeapon() {
		return (selectedWeapons[0] && this->isSword()) ||(selectedWeapons[1] && this->isAxe()) ||(selectedWeapons[2] && this->isBow());
	}

	bool isConsumable() {
		return this->isFood() || this->isPotion();
	}

	bool unlocalizedNameContains(const char* needle1, const char* needle2 = nullptr) {
		if (!this->env || !this->obj) return false;
		jstring jname = this->getUnlocalizedName();
		if (!jname) return false;
		const char* utf = this->env->GetStringUTFChars(jname, nullptr);
		bool match = false;
		if (utf) {
			std::string lower(utf);
			for (auto& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
			if (lower.find(needle1) != std::string::npos) match = true;
			if (!match && needle2 && lower.find(needle2) != std::string::npos) match = true;
			this->env->ReleaseStringUTFChars(jname, utf);
		}
		this->env->DeleteLocalRef(jname);
		return match;
	}

	bool isSword() {
		if (!itemSwordClass) itemSwordClass = mappings->getClass("ItemSword");
		if (itemSwordClass && this->isInstanceOf(itemSwordClass)) return true;
		return this->unlocalizedNameContains("sword");
	}

	bool isFood() {
		if (!itemFoodClass) itemFoodClass = mappings->getClass("ItemFood");
		return this->isInstanceOf(itemFoodClass);
	}

	bool isPotion() {
		if (!itemPotionClass) itemPotionClass = mappings->getClass("ItemPotion");
		return this->isInstanceOf(itemPotionClass);
	}

	bool isBow() {
		if (!itemBowClass) itemBowClass = mappings->getClass("ItemBow");
		if (itemBowClass && this->isInstanceOf(itemBowClass)) return true;
		return this->unlocalizedNameContains("bow");
	}

	bool isFishingRod() {
		if (!itemRodClass) itemRodClass = mappings->getClass("ItemFishingRod");
		return this->isInstanceOf(itemRodClass);
	}

	bool isEnderPearl() {
		if (!itemPearlClass) itemPearlClass = mappings->getClass("ItemEnderPearl");
		return this->isInstanceOf(itemPearlClass);
	}

	bool isAxe() {
		if (!itemAxeClass) itemAxeClass = mappings->getClass("ItemAxe");
		if (itemAxeClass && this->isInstanceOf(itemAxeClass)) return true;
		return this->unlocalizedNameContains("axe", "hatchet");
	}

	bool isArmor() {
		if (!itemArmorClass) itemArmorClass = mappings->getClass("ItemArmor");
		return this->isInstanceOf(itemArmorClass);
	}

	bool isSoup() {
		if (!itemSoupClass) itemSoupClass = mappings->getClass("ItemSoup");
		return this->isInstanceOf(itemSoupClass);
	}

	bool isBlock() {
		if (!itemBlockClass) itemBlockClass = mappings->getClass("ItemBlock");
		return this->isInstanceOf(itemBlockClass);
	}

	bool isWaterBucket() { return getId() == 326; }
	bool isGoldenApple() { return getId() == 322; }
	bool isSnowball()    { return getId() == 332; }
	bool isEgg()         { return getId() == 344; }
	bool isProjectile()  { return isSnowball() || isEgg(); }
};
