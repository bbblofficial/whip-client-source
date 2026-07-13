#pragma once
#include "../../../DllMain.h"
#include "../../../hud/renderer/IArraylistRenderer.h"

#include "module/base/DedicatedThreadBaseModule.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include "wrapper/minecraft/client/multiplayer/worldclient.h"
#include "handler/SettingsHandler.h"
#include "module/base/SharedThreadBaseModule.h"
#include "module/impl/setting/FriendsModule.h"
#include "../setting/EnemiesModule.h"
#include "setting/Setting.h"
#include "setting/SettingMacros.h"
#include "util/mathutils.h"
#include "util/ModuleUtils.h"
#include "util/xor.h"
#include "util/ClientStrings.h"
#include "handler/ModuleHandler.h"
#include "wrapper/minecraft/entity/EntityLivingBase.h"

class AimAssistModule : public DedicatedThreadBaseModule<AimAssistModule, ModuleType::AIM_ASSIST, CategoryType::COMBAT> {
private:
	int currentMode;
	float speed;
	float maxSpeed;
	bool speedunlocker;
	float fovMin;
	float fovMax;
	float distanceMin;
	float distanceMax;
	int priority;
	bool requireClick;
	bool weaponsOnly;
	bool teamMode;
	bool keepOnTarget;
	int keepOnTargetKeybind;
	bool keepOnTargetKeybindPressed = false;
	bool targetEnemiesOnly;
	std::vector<bool> targetEntityType;
	bool breakBlock;
	bool exhaust;
	int exhaustPercent;
	int multipoint;
	FriendsModule* friendsModule = nullptr;
	EnemiesModule* enemiesModule = nullptr;
	struct Target {
		int entityId = -1;
		double distance = 0.0f;
		float yaw = 0.0f;
		float pitch = 0.0f;
		int hurtTime = 0;
	};
	struct AAHorizontalBound {
		double x;
		double z;
	};
	Target lastTarget;
	float maxAddedH;
	float addedH;
	bool cycledH;
	bool upH;
	float randomSpeed;
	int nextRandomSpeed;
	bool pickBlockPressed;
	int multipointSignX = 1;
	int multipointSignZ = -1;

	void getRotationNeeded(EntityClientPlayerMP& thePlayer, EntityLivingBase& player, float* rotBuff) {
		if (!rotBuff) return;

		double thePlayerPos[3]{
			thePlayer.posX(),
			thePlayer.posY(),
			thePlayer.posZ()
		};

		double playerPos[3]{
			player.posX(),
			player.posY() + 1.62f,
			player.posZ()
		};

		if (this->multipoint > 0.0f) {
			double width = randomFloat(0.25, 0.35) * (this->multipoint / 100.0f);

			AAHorizontalBound bounds[4] = {
				{ playerPos[0] - width, playerPos[2] - width },
				{ playerPos[0] - width, playerPos[2] + width },
				{ playerPos[0] + width, playerPos[2] - width },
				{ playerPos[0] + width, playerPos[2] + width }
			};

			double boundsDistances[4] = { 0.0 };
			double selectedBoundDist = 0;
			int selectedBoundIndex = -1;

			for (int i = 0; i < 4; i++) {
				double cBoundDist = sqrt(pow(bounds[i].x - thePlayerPos[0], 2) + pow(bounds[i].z - thePlayerPos[2], 2));
				boundsDistances[i] = cBoundDist;

				if (!selectedBoundDist || selectedBoundDist > cBoundDist) {
					selectedBoundDist = cBoundDist;
					selectedBoundIndex = i;
				}
			}

			if (selectedBoundIndex != -1) {
				playerPos[0] = bounds[selectedBoundIndex].x;
				playerPos[2] = bounds[selectedBoundIndex].z;
			}
		}

		double directions[2];
		direction3D(playerPos, thePlayerPos, directions);

		rotBuff[0] = (angleTo180(fmodf((float)directions[0], 360.0f) - thePlayer.rotationYaw()));
		rotBuff[1] = (angleTo180(directions[1] - thePlayer.rotationPitch()));
	}

	bool isWorseThanTarget(const Target& target, double distance, float yaw, int hurtTime) const {
		if (target.entityId == -1) return false;
		switch (this->priority) {
			case 0: return distance > target.distance;
			case 1: return abs(yaw) > abs(target.yaw);
			case 2:
				if (target.hurtTime == 0 && hurtTime > 0) return true;
				if (target.hurtTime > 0 && hurtTime == 0) return false;
				return distance > target.distance;
			default: return distance > target.distance;
		}
	}

	Target getTarget(WorldClient& theWorld, EntityClientPlayerMP& thePlayer) {
	Target target = { -1, 0.0, 0.0f, 0.0f, 0 };

	if (this->keepOnTarget && this->lastTarget.entityId != -1) {
		Entity currentEntity = theWorld.getEntityByID(this->lastTarget.entityId);
		EntityPlayer currentPlayer = currentEntity.safeConvertTo<EntityPlayer>();

		if (!currentPlayer.isNull()
			&& currentPlayer.entityId() != thePlayer.entityId()
			&& (!this->teamMode || !(thePlayer.isOnSameTeam(currentPlayer) || thePlayer.hasSameNametagColor(currentPlayer)))
			&& !(this->friendsModule != nullptr && this->friendsModule->isFriend(currentPlayer))) {

			double distance = MODULEUTILS_H::getDistance(thePlayer, currentPlayer);
			if (distance > 6.0)
				distance = 6.0;

			float rotations[2]{ 0.0f, 0.0f };
			this->getRotationNeeded(thePlayer, currentPlayer, rotations);

			return { currentPlayer.entityId(), distance, rotations[0], rotations[1], currentPlayer.hurtTime() };
		}
	}

	const bool wantPlayers = !this->targetEntityType.empty() && this->targetEntityType[0];
	const bool wantMobs    = this->targetEntityType.size() > 1 && this->targetEntityType[1];
	const bool allowInvis  = this->targetEntityType.size() > 2 && this->targetEntityType[2];
	const bool allowNaked  = this->targetEntityType.size() > 3 && this->targetEntityType[3];

	if (wantPlayers) {
		ArrayList playerEntities = theWorld.playerEntities();
		if (!playerEntities.isNull()) {
			int playerEntitiesSize = playerEntities.size();
			for (int i = 0; i < playerEntitiesSize; i++) {
				JavaObject playerObj = playerEntities.get(i);
				EntityPlayer player = playerObj.convertTo<EntityPlayer>();

				if (player.isNull()) continue;

				if (thePlayer.entityId() == player.entityId()
					|| (this->teamMode && (thePlayer.isOnSameTeam(player) || thePlayer.hasSameNametagColor(player)))
					|| (!allowNaked && MODULEUTILS_H::isPlayerNaked(player))
					|| (!allowInvis && player.isInvisible())
					|| (this->friendsModule != nullptr && this->friendsModule->isFriend(player))) {
					continue;
				}

				if (this->targetEnemiesOnly && this->enemiesModule != nullptr && !this->enemiesModule->isEnemy(player)) {
					continue;
				}

				double dist = MODULEUTILS_H::getDistance(thePlayer, player);
				float rotations[2]{ 0.0f, 0.0f };
				this->getRotationNeeded(thePlayer, player, rotations);
				float yaw = rotations[0];
				float pitch = rotations[1];

				int ht = player.hurtTime();

				const float minDistEff = (this->priority == 2) ? 0.0f : this->distanceMin;
				const float maxDistEff = (this->priority == 2) ? 3.3f : this->distanceMax;
				if (dist > maxDistEff || dist < minDistEff || abs(yaw) > this->fovMax / 2.0f || abs(yaw) < this->fovMin / 2.0f) continue;

				if (this->priority == 2 && ht > 0) continue;

				if (this->isWorseThanTarget(target, dist, yaw, ht)) continue;

				target = { player.entityId(), dist, yaw, pitch, ht };
			}
		}
	}

	if (wantMobs) {
		ArrayList loadedEntities = theWorld.loadedEntityList();
		if (!loadedEntities.isNull()) {
			int loadedSize = loadedEntities.size();
			for (int i = 0; i < loadedSize; i++) {
				JavaObject obj = loadedEntities.get(i);
				if (obj.isNull()) continue;

				if (!obj.isInstanceOf("EntityLivingBase")) continue;
				if (obj.isInstanceOf("EntityPlayer")) continue;

				EntityLivingBase& mob = obj.safeConvertTo<EntityLivingBase>();

				if (mob.entityId() == thePlayer.entityId()) continue;
				if (!allowInvis && mob.isInvisible()) continue;

				double dist = MODULEUTILS_H::getDistance(thePlayer, mob);
				float rotations[2]{ 0.0f, 0.0f };
				this->getRotationNeeded(thePlayer, mob, rotations);
				float yaw = rotations[0];
				float pitch = rotations[1];

				int ht = mob.hurtTime();

				const float minDistEff = (this->priority == 2) ? 0.0f : this->distanceMin;
				const float maxDistEff = (this->priority == 2) ? 3.3f : this->distanceMax;
				if (dist > maxDistEff || dist < minDistEff || abs(yaw) > this->fovMax / 2.0f || abs(yaw) < this->fovMin / 2.0f) continue;

				if (this->priority == 2 && ht > 0) continue;

				if (this->isWorseThanTarget(target, dist, yaw, ht)) continue;

				target = { mob.entityId(), dist, yaw, pitch, ht };
			}
		}
	}

	return target;
}

protected:
    void onUpdate(JniScope& scope) override;

    void updateRandomSpeed(bool success);

public:
	void onEnable() override {
		DedicatedThreadBaseModule::onEnable();

		if (friendsModule == nullptr) {
			friendsModule = static_cast<FriendsModule*>(ModuleHandler::getInstance().getModule<ModuleType::FRIENDS>());
		}

		if (targetEnemiesOnly && enemiesModule == nullptr) {
			enemiesModule = static_cast<EnemiesModule*>(ModuleHandler::getInstance().getModule<ModuleType::ENEMY>());
		}
	}

	int getThreadPriority() const override {
		return THREAD_PRIORITY_TIME_CRITICAL;
	}

	void onLoad() override {
		DedicatedThreadBaseModule::onLoad();

		setDelayMs(2);

		COMBO_SETTING_CALLBACK(currentMode, SETTING_CALLBACK([this](const int value) {
			this->multipoint = 50;
			if (value == 0) {
				this->exhaust = false;
				this->exhaustPercent = 0;
			} else {
				this->exhaust = true;
				this->exhaustPercent = 50;
			}
		}), Strings::modeBlatant(), Strings::modeLegit());
		FLOAT_SLIDER_CALLBACK(speed, 5.0f, 1.0f, 10.0f, SETTING_CALLBACK([this](const float) {
			this->maxSpeed = this->speed;
		}));
		FLOAT_RANGE_SLIDER_NAMED("fov", fovMin, fovMax, 0.0f, 120.0f, 0.0f, 360.0f);

		{
			auto setting = SettingsHandler::getInstance().createFloatRangeSliderSetting(
				"distance", &distanceMin, &distanceMax, 0.0f, 4.0f, 0.0f, 6.0f,
				SETTING_VISIBILITY(this->priority != 2));
			SettingsHandler::getInstance().addSetting(this, setting);
		}
		COMBO_SETTING(priority, "Distance", "Fov", "HurtTime");
		MULTI_COMBO_SETTING_DEFAULT(targetEntityType, (std::vector<bool>{true, false, false, true}),
			"Players", "Mobs", "Invisible", "Naked");
		BOOL_SETTING_CONDITIONAL(targetEnemiesOnly, false);
		BOOL_SETTING_CONDITIONAL(requireClick, true);
		BOOL_SETTING_CONDITIONAL(weaponsOnly, true);
		BOOL_SETTING_CONDITIONAL(breakBlock, false);
		BOOL_SETTING_CONDITIONAL(keepOnTarget, false);
		KEYBIND_SETTING_CONDITIONAL_OPTIONAL(keepOnTargetKeybind, 0, SETTING_VISIBILITY(this->keepOnTarget));
	}

    AimAssistModule();

	const char* getDisplayName() const override {
		return Strings::modAimAssist();
	}

private:
	mutable char instanceBuffer[64] = {0};

public:
	FORMAT_FLAGS(" %s %.1f", (this->currentMode == 0 ? Strings::modeBlatant() : Strings::modeLegit()), this->speed)
};
