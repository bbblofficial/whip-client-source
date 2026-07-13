#pragma once
#include "../guiscreen.h"
#include "../../../entity/player/EntityPlayer.h"
#include "util/Debug.h"

class GuiInventory : public GuiScreen {
private:
	static jclass guiInventoryClass;
	static jmethodID constructorId;

public:
	GuiInventory(JNIEnv* env, jobject obj) : GuiScreen::GuiScreen(env, obj) {}

	static GuiInventory newInstance(JNIEnv* env, EntityPlayer thePlayer) {
		if (!guiInventoryClass) guiInventoryClass = mappings->getClass("GuiInventory");
		if (!guiInventoryClass) {
			return { NULL, NULL };
		}
		if (!constructorId) constructorId = mappings->getMethod("GuiInventory#<init>");

		if (!constructorId) {
			return { NULL, NULL };
		}

		jobject obj = env->NewObject(guiInventoryClass, constructorId, thePlayer.getObj());

		return { env, obj };
	}
};
