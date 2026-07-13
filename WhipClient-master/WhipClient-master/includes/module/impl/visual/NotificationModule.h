#pragma once

#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include "util/ClientStrings.h"
#include <vector>
#include <string>
#include <chrono>
#include <imgui.h>
#include <map>

#include "bus/EventBus.h"
#include "event/sub/UpdateEvent.h"
#include "module/base/SettingBaseModule.h"

struct Notification {
    char* message;
    size_t messageSize;
    ImColor color;
    float opacity;
    std::chrono::steady_clock::time_point createTime;
    float animationProgress;
    bool isEntering;
    bool rendered;

    Notification() : message(nullptr), messageSize(0), color(ImColor(255, 255, 255, 255)),
                     opacity(0.0f), animationProgress(0.0f), isEntering(true), rendered(false)  {}

    ~Notification();

    Notification(const Notification&) = delete;
    Notification& operator=(const Notification&) = delete;

    Notification(Notification&& other) noexcept;
    Notification& operator=(Notification&& other) noexcept;

    void setMessage(const std::string& msg);
    const char* getMessage() const { return message ? message : ""; }

    void clearMessageAfterRender();
};

class NotificationModule final : public SettingBaseModule<NotificationModule, ModuleType::NOTIFICATION, CategoryType::VISUAL> {
public:
    enum class Position {
        BOTTOM_RIGHT = 0,
        BOTTOM_LEFT = 1,
        TOP_LEFT = 2,
        TOP_RIGHT = 3,
    };

    inline static int position = static_cast<int>(Position::BOTTOM_RIGHT);
    inline static float marginX = 0.0f;
    inline static float marginY = 10.0f;
    inline static float spacingY = 5.0f;
    inline static float scale = 1.0f;
    inline static float notificationLifetime = 2.0f;
    inline static float animationDuration = 0.3f;
    inline static auto successColor = ImColor(0, 255, 0, 255);
    inline static auto errorColor = ImColor(255, 0, 0, 255);
    inline static auto infoColor = ImColor(0, 150, 255, 255);

private:
    std::vector<Notification> notifications;
    std::map<std::string, bool> moduleStates;

    void removeExpiredNotifications();
    void updateNotificationAnimations();

public:
    NotificationModule();

    ~NotificationModule();

    void onUpdate();

    void onLoad() override {
        SettingBaseModule::onLoad();

        COMBO_SETTING(position, Strings::posBottomRight(), Strings::posBottomLeft(), Strings::posTopLeft(), Strings::posTopRight());
        FLOAT_SLIDER_CONDITIONAL(scale, 1.0f, 0.5f, 2.0f);
        COLOR_SETTING_CONDITIONAL_OPTIONAL(successColor, ImColor(0, 255, 0, 255), SETTING_VISIBILITY(TRUE));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(errorColor, ImColor(255, 0, 0, 255), SETTING_VISIBILITY(TRUE));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(infoColor, ImColor(0, 150, 255, 255), SETTING_VISIBILITY(TRUE));
        FLOAT_SLIDER(marginX, 0.0f, 0.0f, 100.0f);
        FLOAT_SLIDER(marginY, 15.0f, 0.0f, 100.0f);
        FLOAT_SLIDER(spacingY, 5.0f, 0.0f, 20.0f);
        FLOAT_SLIDER_CONDITIONAL(notificationLifetime, 2.0f, 1.0f, 10.0f);
        FLOAT_SLIDER_CONDITIONAL(animationDuration, 0.3f, 0.1f, 1.0f);
    }

    void onEnable() override {
       subscribe<UpdateEvent>([this](const UpdateEvent& event) {
            if (this->enable) {
                this->onUpdate();
            }
        });
    }

    void onDisable() override {
        EventBus::getInstance().unsubscribe(this);
        clearAllNotifications();
    }

    [[nodiscard]] bool enableOnLoad() const override {
        return true;
    }

    float calculateAnimationOffset(const Notification& notification) const;
    void putNofication(Notification& notification);
    void addNotification(std::string moduleName, bool enabled);
    void addMessageNotification(std::string message, ImColor color);
    void addMessageNotificationForced(std::string message, ImColor color);
    ImVec2 calculateNotificationPosition(float width, float height, float screenWidth, float screenHeight, int index) const;
    void clearAllNotifications();

    [[nodiscard]] std::vector<Notification>& getNotifications() { return notifications; }

    static void addCustomNotification(std::string message, ImColor color);
    static void addModuleNotification(std::string moduleName, bool enabled);
};
