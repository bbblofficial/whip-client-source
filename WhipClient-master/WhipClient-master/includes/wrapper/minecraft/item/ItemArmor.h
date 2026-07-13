#pragma once

#include "Item.h"

class ItemArmor : public Item {
	static jfieldID armorTypeId;
	static jfieldID damageReduceAmountId;

public:
	ItemArmor(JNIEnv* env, jobject obj) : Item(env, obj) {}

	int armorType() {
		if (!armorTypeId) armorTypeId = mappings->getField("ItemArmor#armorType");
		return this->env->GetIntField(this->obj, armorTypeId);
	}

	int damageReduceAmount() {
		if (!damageReduceAmountId) damageReduceAmountId = mappings->getField("ItemArmor#damageReduceAmount");
		return this->env->GetIntField(this->obj, damageReduceAmountId);
	}
};
