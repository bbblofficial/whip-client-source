#include "../../../../includes/wrapper/minecraft/client/Minecraft.h"

jclass Minecraft::minecraftClass = NULL;
jfieldID Minecraft::theMinecraftId = NULL;
jfieldID Minecraft::inGameHasFocusId = NULL;
jfieldID Minecraft::theWorldId = NULL;
jfieldID Minecraft::TimerID = NULL;
jfieldID Minecraft::thePlayerId = NULL;
jfieldID Minecraft::objectMouseOverId = NULL;
jfieldID Minecraft::playerControllerId = NULL;
jfieldID Minecraft::currentScreenId = NULL;
jfieldID Minecraft::gameSettingsId = NULL;
jfieldID Minecraft::pointedEntityId = NULL;
jfieldID Minecraft::SetPointedEntityId = NULL;
jmethodID Minecraft::displayGuiScreenId = NULL;
jmethodID Minecraft::RenderManagerID = NULL;

jmethodID Minecraft::movingObjectPosConstructorId = NULL;
jfieldID Minecraft::setObjectMouseOverId = NULL;
jmethodID Minecraft::cancelClickMouseId = NULL;
jmethodID Minecraft::setIngameFocusId = NULL;

jfieldID Minecraft::rightClickDelayTimerId = NULL;
jfieldID Minecraft::SetRightClickDelayTimerId = NULL;
jfieldID Minecraft::lefClickCounter = NULL;

jfieldID Minecraft::displayWidthId = NULL;
jfieldID Minecraft::displayHeightId = NULL;

jmethodID Minecraft::onItemRightClickId = NULL;

jfieldID Minecraft::caughtEntityId = NULL;
jmethodID Minecraft::getSessionId = NULL;

jfieldID Minecraft::getRenderViewEntityId = NULL;

jfieldID Minecraft::mcProfilerId = NULL;
jclass Minecraft::entityClass = NULL;

jclass Minecraft::profilerClass = NULL;

jfieldID Minecraft::entityRendererId = NULL;

jfieldID Minecraft::fullScreenId = NULL;
jmethodID Minecraft::unicodeId = NULL;

jclass Minecraft::PacketThreadUtilClass = NULL;

jmethodID Minecraft::getNetHandlerId = NULL;
jmethodID Minecraft::rightClickMouseId = NULL;
jmethodID Minecraft::closeScreenId = NULL;

jfieldID Minecraft::myNetworkManagerId = NULL;

jclass Minecraft::entityPlayerClass = NULL;

jfieldID Minecraft::renderEngineId = NULL;
jfieldID Minecraft::renderItemId = NULL;
jfieldID Minecraft::currentServerDataId = nullptr;

ItemStack Minecraft::onItemRightClick(ItemStack itemStack, World world, EntityPlayer player) {
	if (!onItemRightClickId) onItemRightClickId = mappings->getMethod("Item#onItemRightClick");

	return ItemStack(this->env, this->env->CallObjectMethod(this->obj, onItemRightClickId,
		itemStack.getObj(),
		world.getObj(),
		player.getObj()));
}
