#pragma once
#include "../../../../../includes/wrapper/primitive/JavaObject.h"

class GuiScreen : public JavaObject {
	static jclass guiInventoryClass;
	static jclass guiChestClass;
	static jclass guiOptionsClass;
	static jclass guiChatClass;

public:
	GuiScreen() : JavaObject(nullptr, nullptr) {}
	GuiScreen(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

	bool isInventory() {
		if (!guiInventoryClass) guiInventoryClass = mappings->getClass("GuiInventory");

		return this->isInstanceOf(guiInventoryClass);
	}

	bool isChest() {
		if (!guiChestClass) guiChestClass = mappings->getClass("GuiChest");

		return this->isInstanceOf(guiChestClass);
	}

	bool isOptions() {
		if (!guiOptionsClass) guiOptionsClass = mappings->getClass("GuiOptions");

		return this->isInstanceOf(guiOptionsClass);
	}

	bool isChat() {
		if (!guiChatClass) guiChatClass = mappings->getClass("GuiChat");

		return this->isInstanceOf(guiChatClass);
	}
};
