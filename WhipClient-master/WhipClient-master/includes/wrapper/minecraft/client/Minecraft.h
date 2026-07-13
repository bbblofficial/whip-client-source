#pragma once

#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "./multiplayer/worldclient.h"
#include "./entity/entityclientplayermp.h"
#include "./multiplayer/playercontrollermp.h"
#include "./gui/guiscreen.h"
#include "../util/movingobjectposition.h"
#include "./settings/gamesettings.h"
#include "./network/nethandlerplayclient.h"
#include "./activerenderinfo/activerenderinfo.h"
#include "../util/timer.h"
#include "../entity/Render/rendermanager.h"
#include "session/Session.h"
#include "../profiler/profiler.h"
#include "renderer/entityrenderer.h"
#include "wrapper/minecraft/network/NetworkManager.h"
#include "texture/TextureManager.h"
#include "renderer/RenderItem.h"
#include "./multiplayer/ServerData.h"

class ItemStack;
class World;
class EntityPlayer;

class Minecraft : public JavaObject {
	static jclass minecraftClass;
	static jfieldID theMinecraftId;

	static jfieldID inGameHasFocusId;
	static jfieldID theWorldId;
	static jfieldID TimerID;
	static jfieldID thePlayerId;
	static jfieldID objectMouseOverId;
	static jfieldID playerControllerId;
	static jfieldID currentScreenId;
	static jfieldID gameSettingsId;
	static jfieldID pointedEntityId;
	static jfieldID SetPointedEntityId;

	static jmethodID getNetHandlerId;
	static jmethodID displayGuiScreenId;
	static jmethodID RenderManagerID;

	static jmethodID movingObjectPosConstructorId;
	static jfieldID setObjectMouseOverId;
	static jmethodID cancelClickMouseId;

	static jfieldID rightClickDelayTimerId;
	static jfieldID SetRightClickDelayTimerId;
	static jfieldID lefClickCounter;

	static jfieldID displayWidthId;
	static jfieldID displayHeightId;

	static jmethodID onItemRightClickId;

	static jfieldID caughtEntityId;

	static jmethodID getSessionId;

	static jfieldID getRenderViewEntityId;

	static jfieldID mcProfilerId;

	static jclass entityClass;

	static jclass profilerClass;

	static jfieldID entityRendererId;

	static jfieldID fullScreenId;

	static jmethodID unicodeId;
	static jmethodID rightClickMouseId;
	static jmethodID closeScreenId;
	static jmethodID setIngameFocusId;

	static jclass PacketThreadUtilClass;

	static jfieldID myNetworkManagerId;

	static jclass entityPlayerClass;

	static jfieldID renderEngineId;
	static jfieldID renderItemId;
	static jfieldID currentServerDataId;

public:
	Minecraft(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

	static Minecraft getMinecraft(JNIEnv* env) {
		if (!minecraftClass) minecraftClass = mappings->getClass("Minecraft");
		if (!theMinecraftId) theMinecraftId = mappings->getField("Minecraft#theMinecraft");

		jobject obj = env->GetStaticObjectField(minecraftClass, theMinecraftId);
		if (!obj) return { env, nullptr };

		return { env, obj };
	}

	bool isEntityPlayer(JNIEnv* env, jobject entity) {
		if (!entity) return false;

		if (!entityPlayerClass) {
			entityPlayerClass = mappings->getClass("EntityPlayer");
			if (!entityPlayerClass) return false;
		}

		return env->IsInstanceOf(entity, entityPlayerClass);
	}

	bool inGameHasFocus() {
		if (!inGameHasFocusId) inGameHasFocusId = mappings->getField("Minecraft#inGameHasFocus");

		return this->env->GetBooleanField(this->obj, inGameHasFocusId);
	}

	bool isFullScreen() {
		if (!fullScreenId) fullScreenId = mappings->getField("Minecraft#fullscreen");

		return this->env->GetBooleanField(this->obj, fullScreenId);
	}

	EntityRenderer getEntityRender() {
		if (!entityRendererId) entityRendererId = mappings->getField("Minecraft#theWorld");

		jobject obj = this->env->GetObjectField(this->obj, entityRendererId);
		if (!obj) return { env, NULL };

		return { this->env, obj };
	}

	void rightClickMouse() {
		if (!rightClickMouseId) rightClickMouseId = mappings->getMethod("Minecraft#rightClickMouse");

		this->env->CallVoidMethod(this->obj, rightClickMouseId);
	}

	int rightClickDelayTimer() {
		if (!rightClickDelayTimerId) rightClickDelayTimerId = mappings->getField("Minecraft#rightClickDelayTimer");
		return this->env->GetIntField(this->obj, rightClickDelayTimerId);
	}

	void setRightClickDelayTimer(int delay) {
		if (!SetRightClickDelayTimerId) SetRightClickDelayTimerId = mappings->getField("Minecraft#rightClickDelayTimer");
		this->env->SetIntField(this->obj, SetRightClickDelayTimerId, delay);
	}

	void setLeftClickDelayTimer(int delay) {
		if (!lefClickCounter) lefClickCounter = mappings->getField("Minecraft#leftClickCounter");
		this->env->SetIntField(this->obj, lefClickCounter, delay);
	}

	WorldClient theWorld() {
		if (!theWorldId) theWorldId = mappings->getField("Minecraft#theWorld");

		jobject obj = this->env->GetObjectField(this->obj, theWorldId);
		if (!obj) return { env, NULL };

		return { this->env, obj };
	}

	EntityClientPlayerMP thePlayer() {
		if (!thePlayerId) thePlayerId = mappings->getField("Minecraft#thePlayer");

		jobject obj = this->env->GetObjectField(this->obj, thePlayerId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	static jclass getEntityClass() {
		if (!entityClass) entityClass = mappings->getClass("Entity");
		return entityClass;
	}

	static jclass getPacketThreadUtilClass() {
		if (!PacketThreadUtilClass) PacketThreadUtilClass = mappings->getClass("PacketThreadUtil");
		return PacketThreadUtilClass;
	}

	Profiler getMcProfiler() {
		if (!mcProfilerId) mcProfilerId = mappings->getField("Minecraft#mcProfiler");

		jobject obj = this->env->GetObjectField(this->obj, mcProfilerId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	static jclass getProfiler() {
		if (!profilerClass) profilerClass = mappings->getClass("Profiler");
		return profilerClass;
	}

	Entity getRenderViewEntity() {
		if (!getRenderViewEntityId) getRenderViewEntityId = mappings->getField("Minecraft#renderViewEntity");

		jobject obj = this->env->GetObjectField(this->obj, getRenderViewEntityId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	EntityLivingBase GetRenderViewEntity() {
		if (!getRenderViewEntityId) getRenderViewEntityId = mappings->getField("Minecraft#renderViewEntity");

		jobject obj = this->env->GetObjectField(this->obj, getRenderViewEntityId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	Session getSession() {
		if (!getSessionId) getSessionId = mappings->getMethod("Minecraft#getSession");

		jobject obj = this->env->CallObjectMethod(this->obj, getSessionId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	Entity caughtEntity() {
		if (!caughtEntityId) caughtEntityId = mappings->getField("EntityFishHook#caughtEntity");

		jobject obj = this->env->GetObjectField(this->obj, caughtEntityId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	MovingObjectPosition objectMouseOver() {
		if (!objectMouseOverId) objectMouseOverId = mappings->getField("Minecraft#objectMouseOver");

		jobject obj = this->env->GetObjectField(this->obj, objectMouseOverId);
		if (!obj) return { this->env, NULL };

		return { this->env, obj };
	}

	void setObjectMouseOver(MovingObjectPosition* position) {
		if (!objectMouseOverId) objectMouseOverId = mappings->getField("Minecraft#objectMouseOver");

		this->env->SetObjectField(this->obj, objectMouseOverId, position ? position->getObj() : NULL);
	}

	PlayerControllerMP playerController() {
		if (!playerControllerId) playerControllerId = mappings->getField("Minecraft#playerController");

		jobject obj = this->env->GetObjectField(this->obj, playerControllerId);
		if (!obj) return { this->env, NULL };

		return { this->env, obj };
	}

	Timer timer() {
		if (!TimerID) TimerID = mappings->getField("Minecraft#timer");

		jobject obj = this->env->GetObjectField(this->obj, TimerID);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	RenderManager getRenderManager() {
		if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
			if (!RenderManagerID) RenderManagerID = mappings->getMethod("Minecraft#getRenderManager");
			jobject obj = this->env->CallObjectMethod(this->obj, RenderManagerID);
			if (!obj) return { NULL, NULL };
			return { this->env, obj };
		}
		else {
			return { this->env, NULL };
		}
	}

	ActiveRenderInfo activeRenderInfo() {
		return { this->env, NULL };
	}

	GuiScreen currentScreen() {
		if (!currentScreenId) currentScreenId = mappings->getField("Minecraft#currentScreen");

		jobject obj = this->env->GetObjectField(this->obj, currentScreenId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	void closeScreen() {
		if (!currentScreenId) currentScreenId = mappings->getField("Minecraft#currentScreen");

		this->env->SetObjectField(this->obj, currentScreenId, nullptr);
	}

	GameSettings gameSettings() {
		if (!gameSettingsId) gameSettingsId = mappings->getField("Minecraft#gameSettings");

		jobject obj = this->env->GetObjectField(this->obj, gameSettingsId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	Entity pointedEntity() {
		if (!pointedEntityId) pointedEntityId = mappings->getField("Minecraft#pointedEntity");

		jobject obj = this->env->GetObjectField(this->obj, pointedEntityId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	void setPointedEntity(Entity entity) {
		if (!pointedEntityId) pointedEntityId = mappings->getField("Minecraft#pointedEntity");

		this->env->SetObjectField(this->obj, pointedEntityId, entity.getObj());
	}

	NetHandlerPlayClient getNetHandler() {
		if (!getNetHandlerId) getNetHandlerId = mappings->getMethod("Minecraft#getNetHandler");

		jobject obj = this->env->CallObjectMethod(this->obj, getNetHandlerId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	ItemStack onItemRightClick(ItemStack itemStack, World world, EntityPlayer player);

	void displayGuiScreen(GuiScreen guiScreen) {
		if (!displayGuiScreenId) displayGuiScreenId = mappings->getMethod("Minecraft#displayGuiScreen");

		this->env->CallVoidMethod(this->obj, displayGuiScreenId, guiScreen.getObj());
	}

	void displayGuiScreen() {
		if (!displayGuiScreenId)
			displayGuiScreenId = mappings->getMethod("Minecraft#displayGuiScreen");

		this->env->CallVoidMethod(this->obj, displayGuiScreenId, nullptr);
	}

	void SetPointedEntity(Entity entity) {
		if (!SetPointedEntityId) SetPointedEntityId = mappings->getField("Minecraft#pointedEntity");
		this->env->SetObjectField(this->obj, SetPointedEntityId, entity.getObj());
	}

	void SetPointedEntity() {
		if (!SetPointedEntityId) SetPointedEntityId = mappings->getField("Minecraft#pointedEntity");
		this->env->SetObjectField(this->obj, SetPointedEntityId, NULL);
	}

	void cancelClickMouse() {
		if (!cancelClickMouseId) cancelClickMouseId = mappings->getMethod("Minecraft#clickMouse");
		this->env->CallVoidMethod(this->obj, cancelClickMouseId);
	}

	void setIngameFocus() {
		if (!setIngameFocusId) setIngameFocusId = mappings->getMethod("Minecraft#setIngameFocus");
		this->env->CallVoidMethod(this->obj, setIngameFocusId);
	}

	bool isUnicode() {
		if (!unicodeId) unicodeId = mappings->getMethod("Minecraft#isUnicode");
		return this->env->CallBooleanMethod(this->obj, unicodeId);
	}

	void setObjectMouseOver(MovingObjectPosition movingObjectPosition) {
		if (!setObjectMouseOverId) setObjectMouseOverId = mappings->getField("Minecraft#objectMouseOver");
		this->env->SetObjectField(this->obj, setObjectMouseOverId, movingObjectPosition.getObj());
	}

	int displayWidth() {
		if (!displayWidthId) displayWidthId = mappings->getField("Minecraft#displayWidth");
		return this->env->GetIntField(this->obj, displayWidthId);
	}

	int displayHeight() {
		if (!displayHeightId) displayHeightId = mappings->getField("Minecraft#displayHeight");
		return this->env->GetIntField(this->obj, displayHeightId);
	}

	TextureManager getTextureManager() {
		if (!renderEngineId) renderEngineId = mappings->getField("Minecraft#renderEngine");

		jobject obj = this->env->GetObjectField(this->obj, renderEngineId);
		if (!obj) return { this->env, nullptr };

		return { this->env, obj };
	}

	RenderItem getRenderItem() {
		if (!renderItemId) renderItemId = mappings->getField("Minecraft#renderItem");

		jobject obj = this->env->GetObjectField(this->obj, renderItemId);
		if (!obj) return { this->env, nullptr };

		return { this->env, obj };
	}

	ServerData getCurrentServerData() {
		if (!currentServerDataId) currentServerDataId = mappings->getField("Minecraft#currentServerData");

		jobject obj = this->env->GetObjectField(this->obj, currentServerDataId);
		if (!obj) return { this->env, nullptr };

		return { this->env, obj };
	}
};
