#pragma once

#include "../../entity/player/EntityPlayer.h"
#include "../../util/text/ichatcomponent.h"
#include "../../../../../includes/util/StringUtils.h"
#include "../../entity/item/entityitem.h"
#include "../../util/mouvementinput.h"

class EntityClientPlayerMP : public EntityPlayer {
private:
	static jmethodID sendHorseInteractionId;
	static jmethodID dropOneItemId;
	static jfieldID movementInputId;
	static jfieldID sprintToggleTimerId;

public:
	EntityClientPlayerMP(JNIEnv* env, jobject obj) : EntityPlayer::EntityPlayer(env, obj) {}

	bool hasSameNametagColor(EntityPlayer& player) {
		auto getTeam = [](EntityPlayer& e) -> wchar_t {
			IChatComponent playerFormattedName = e.getFormattedCommandSenderName();
			if (playerFormattedName.isNull()) {
				return (wchar_t)0;
			}
			JavaString a = playerFormattedName.getFormattedText();
			if (a.isNull()) {
				return (wchar_t)0;
			}
			wchar_t* b = a.get();
			if (b) {
				wchar_t playerTeamColor = getTextFirstColorCode(b);
				a.release(b);
				return playerTeamColor;
			}
			return (wchar_t)0;
			};

		wchar_t myTeamColor = getTeam(*this);
		wchar_t otherTeamColor = getTeam(player);

		return (myTeamColor != 0 && otherTeamColor != 0 && myTeamColor == otherTeamColor);
	}

	void sendHorseInteraction() {
		if (!sendHorseInteractionId) sendHorseInteractionId = mappings->getMethod("EntityPlayerSP#sendHorseInventory");

		this->env->CallVoidMethod(this->obj, sendHorseInteractionId);
	}

	EntityItem dropOneItem(bool dropAll) {
		if (!dropOneItemId) dropOneItemId = mappings->getMethod("EntityPlayerSP#dropOneItem");

		jobject obj = this->env->CallObjectMethod(this->obj, dropOneItemId, dropAll);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	MouvementInput getMovementInput() {
		if (!movementInputId) movementInputId = mappings->getField("EntityPlayerSP#movementInput");

		jobject obj = this->env->GetObjectField(this->obj, movementInputId);
		if (!obj) return { this->env, NULL };

		return { this->env, obj };
	}

	int getSprintToggleTimer() {
		if (!sprintToggleTimerId) sprintToggleTimerId = mappings->getField("EntityPlayerSP#sprintToggleTimer");

		return this->env->GetIntField(this->obj, sprintToggleTimerId);
	}

	void setSprintToggleTimer(int sprintToggleTimer) {
		if (!sprintToggleTimerId) sprintToggleTimerId = mappings->getField("EntityPlayerSP#sprintToggleTimer");

		this->env->SetIntField(this->obj, sprintToggleTimerId, sprintToggleTimer);
	}
};
