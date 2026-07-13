#include "../../../../includes/module/impl/setting/FriendsModule.h"
#include <widgets.h>
#include "../../../../includes/module/impl/visual/NotificationModule.h"
#include "../../../../includes/wrapper/java/util/UUID.h"
#include "../../../../includes/handler/ModuleHandler.h"
#include "../../../../includes/setting/SettingMacros.h"
#include "util/ClientStrings.h"
#include "wrapper/minecraft/client/minecraft.h"
#include "manager/ConfigManager.h"
#include "handler/ProviderHandler.h"
#include "provider/impl/GameStateProvider.h"

bool FriendsModule::isFriend(Entity& entity) {
    if (!this->enable) return false;

    const JavaUUID entityUUID = entity.getEntityUniqueID();
    if (entityUUID.isNull()) {
        return false;
    }

    UUIDData entityUUIDData = entityUUID.toUUIDData();
    for (auto friendUUIDData : friendUUIDEntities) {
        if (entityUUIDData.equals(friendUUIDData)) {
            return true;
        }
    }
    return false;
}

void FriendsModule::addFriend(Entity entity) {
    if (isFriend(entity)) {
        return;
    }

    friendEntities.push_back(entity.entityId());

    auto entityUUID = entity.getEntityUniqueID();
    if (entityUUID.isNull()) {
        return;
    }

    UUIDData entityUUIDData = entityUUID.toUUIDData();
    friendUUIDEntities.push_back(entityUUIDData);
}

void FriendsModule::removeFriend(Entity entity) {
    auto position = find(friendEntities.begin(), friendEntities.end(), entity.entityId());
    if (position != friendEntities.end()) {
        friendEntities.erase(position);
    }

    auto entityUUID = entity.getEntityUniqueID();
    if (entityUUID.isNull()) {
        return;
    }

    UUIDData entityUUIDData = entityUUID.toUUIDData();
    auto uuidPosition = std::find_if(friendUUIDEntities.begin(), friendUUIDEntities.end(),
        [&entityUUIDData](const UUIDData& friendUUIDData) {
            return entityUUIDData.equals(friendUUIDData);
        });

    if (uuidPosition != friendUUIDEntities.end()) {
        friendUUIDEntities.erase(uuidPosition);
    }
}

void FriendsModule::clearFriends() {
    friendEntities.clear();
    friendUUIDEntities.clear();
}

int FriendsModule::getFriendCount() const {
    return friendUUIDEntities.size();
}

double FriendsModule::getDistance(EntityClientPlayerMP& thePlayer, EntityPlayer& player) {
    return sqrt(pow(thePlayer.posX() - player.posX(), 2)
        + pow(thePlayer.posY() - player.posY(), 2)
        + pow(thePlayer.posZ() - player.posZ(), 2));
}

void FriendsModule::onUpdate(JniScope& scope) {
    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState || !gameState->inGameHasFocus()) return;

    if (this->clearFriendsKey != 0) {
        if (GetAsyncKeyState(this->clearFriendsKey) & 0x8000) {
            if (!this->clearKeyWasPressed) {
                std::string message = std::to_string(getFriendCount()) + Strings::msgFriendsRemoved();
                this->clearFriends();
                NotificationModule::addCustomNotification(message, this->REMOVED_COLOR);
                secureErase(message);
                this->clearKeyWasPressed = true;
            }
        }
        else {
            this->clearKeyWasPressed = false;
        }
    }

    Minecraft theMc = Minecraft::getMinecraft(scope.getEnv());
    if (theMc.isNull()) return;

    if (this->addNearbyFriendsKey != 0) {
        if (GetAsyncKeyState(this->addNearbyFriendsKey) & 0x8000) {
            if (!this->addNearbyKeyWasPressed) {
                this->addNearbyKeyWasPressed = true;

                WorldClient theWorld = theMc.theWorld();

                if (theWorld.isNull()) {
                    return;
                }

                EntityClientPlayerMP thePlayer = theMc.thePlayer();
                if (thePlayer.isNull()) {
                    return;
                }

                ArrayList playerEntities = theWorld.playerEntities();
                if (playerEntities.isNull()) return;
                JNIEnv* _env = scope.getEnv();

                int oldSize = getFriendCount();

                int playerEntitiesSize = playerEntities.size();
                if (_env->ExceptionCheck()) { _env->ExceptionClear(); return; }
                for (int i = 0; i < playerEntitiesSize; i++) {
                    JavaObject playerObj = playerEntities.get(i);
                    if (_env->ExceptionCheck()) { _env->ExceptionClear(); break; }
                    EntityPlayer player = playerObj.convertTo<EntityPlayer>();

                    if (player.isNull() || thePlayer.entityId() == player.entityId()) {
                        continue;
                    }

                    double distance = getDistance(thePlayer, player);
                    if (distance > 15) {
                        continue;
                    }

                    addFriend(player);
                }
                std::string message = std::to_string(getFriendCount() - oldSize) + Strings::msgFriendsAdded();
                NotificationModule::addCustomNotification(message, this->ADDED_COLOR);
                secureErase(message);
            }
        }
        else {
            addNearbyKeyWasPressed = false;
        }
    }

    Entity pointedEntity = theMc.pointedEntity();

    if (this->addFriendsKey == 0) {
        return;
    }

    if (!pointedEntity.isNull()) {
        if (GetAsyncKeyState(addFriendsKey) & 0x8000) {
            if (!pickBlockPressed) {
                pickBlockPressed = true;

                auto position = find(friendEntities.begin(), friendEntities.end(), pointedEntity.entityId());

                if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
                    jstring entityName = pointedEntity.getName();
                    std::string name = JavaString::jstringToString(scope.getEnv(), entityName);

                    if (position == friendEntities.end()) {
                        addFriend(pointedEntity);
                        std::string message = name + Strings::msgFriendAdded();
                        NotificationModule::addCustomNotification(message, this->ADDED_COLOR);
                        SecureZeroMemory(message.data(), message.capacity());
                        message.clear();
                    }
                    else {
                        removeFriend(pointedEntity);
                        std::string message = name + Strings::msgFriendRemoved();
                        NotificationModule::addCustomNotification(message, this->REMOVED_COLOR);
                        SecureZeroMemory(message.data(), message.capacity());
                        message.clear();
                    }

                    secureErase(name);
                }
                else {
                    if (position == friendEntities.end()) {
                        addFriend(pointedEntity);
                        NotificationModule::addCustomNotification(Strings::msgFriendAddedCap(), this->ADDED_COLOR);
                    }
                    else {
                        removeFriend(pointedEntity);
                        NotificationModule::addCustomNotification(Strings::msgFriendRemovedCap(), this->REMOVED_COLOR);
                    }
                }
            }
        }
        else if (pickBlockPressed) {
            pickBlockPressed = false;
        }
    }
}

REGISTER_MODULE(FriendsModule, ModuleType::FRIENDS)
