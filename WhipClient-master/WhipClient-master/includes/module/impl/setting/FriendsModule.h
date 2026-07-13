#pragma once
#include "../../../hud/renderer/IArraylistRenderer.h"
#include "../../base/SharedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include <vector>
#include <imgui.h>
#include "../../../wrapper/java/util/UUID.h"
#include "util/xor.h"
#include "util/ClientStrings.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"

class FriendsModule final : public SharedThreadBaseModule<FriendsModule, ModuleType::FRIENDS, CategoryType::SETTING> {
    std::vector<int> friendEntities;
    std::vector<UUIDData> friendUUIDEntities;
    bool pickBlockPressed = false;
    int clearFriendsKey = 0;
    int addFriendsKey = 4;
    bool clearKeyWasPressed = false;
    int addNearbyFriendsKey = 0;
    bool addNearbyKeyWasPressed = false;

    static constexpr ImColor ADDED_COLOR = ImColor(135, 206, 235, 255);
    static constexpr ImColor REMOVED_COLOR = ImColor(255, 87, 87, 255);

protected:
    void onUpdate(JniScope& scope) override;

public:
    FriendsModule() = default;

    void onLoad() override {
        SharedThreadBaseModule::onLoad();

        KEYBIND_SETTING_CONDITIONAL(addFriendsKey, 4);
        KEYBIND_SETTING_CONDITIONAL(addNearbyFriendsKey, 0);
        KEYBIND_SETTING_CONDITIONAL(clearFriendsKey, 0);

        BUTTON_SETTING_CONDITIONAL(Strings::btnClearAllFriends(), [this]() {
            if (getFriendCount() > 0) {
                std::string message = std::to_string(getFriendCount()) + Strings::msgFriendsRemoved();
                clearFriends();
                NotificationModule::addCustomNotification(message, REMOVED_COLOR);
                SecureZeroMemory(message.data(), message.capacity());
                message.clear();
            } else {
                NotificationModule::addCustomNotification(Strings::msgNoFriendsToRemove(), REMOVED_COLOR);
            }
        });
        BUTTON_SETTING_CONDITIONAL(Strings::btnRemoveLastFriend(), [this]()
        {
            if (!friendEntities.empty()) {
                friendEntities.pop_back();
                friendUUIDEntities.pop_back();
            }
        });
    }

    bool isFriend(Entity& entity);
    void onCleanup() override {
        clearInstanceBuffer();
    }

    void addFriend(Entity entity);
    void removeFriend(Entity entity);
    void clearFriends();
    int getFriendCount() const;

    void addFriendById(int id) { friendEntities.push_back(id); }

    const std::vector<int>& getFriendEntities() const { return friendEntities; }
    const std::vector<UUIDData>& getFriendUUIDEntities() const { return friendUUIDEntities; }

private:
	mutable char instanceBuffer[64] = {0};

public:

    FORMAT_FLAGS("%d", getFriendCount())

private:
    double getDistance(EntityClientPlayerMP& thePlayer, EntityPlayer& player);
};
