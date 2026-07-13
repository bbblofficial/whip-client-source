#include "../../../../includes/module/impl/visual/NotificationModule.h"
#include "../../../../includes/manager/ConfigManager.h"
#include <sstream>
#include "handler/ModuleHandler.h"
#include "handler/ProviderHandler.h"
#include "provider/impl/GameStateProvider.h"
#include "util/ClientStrings.h"
#include "util/TrackedString.h"
#include "wrapper/minecraft/client/Minecraft.h"

Notification::~Notification() {
    if (message) {
        TrackedStringRegistry::instance().untrack(message);

        if (messageSize > 0) {
            SecureZeroMemory(message, messageSize);
        }

        TrackedStringRegistry::instance().deallocate(message);
        message = nullptr;
        messageSize = 0;
    }
}

Notification::Notification(Notification&& other) noexcept
    : message(other.message), messageSize(other.messageSize),
      color(other.color), opacity(other.opacity),
      createTime(other.createTime), animationProgress(other.animationProgress),
      isEntering(other.isEntering), rendered(other.rendered) {
    other.message = nullptr;
    other.messageSize = 0;
}

Notification& Notification::operator=(Notification&& other) noexcept {
    if (this != &other) {
        if (message) {
            TrackedStringRegistry::instance().untrack(message);
            if (messageSize > 0) {
                SecureZeroMemory(message, messageSize);
            }
            TrackedStringRegistry::instance().deallocate(message);
        }

        message = other.message;
        messageSize = other.messageSize;
        color = other.color;
        opacity = other.opacity;
        createTime = other.createTime;
        animationProgress = other.animationProgress;
        isEntering = other.isEntering;
        rendered = other.rendered;

        other.message = nullptr;
        other.messageSize = 0;
    }
    return *this;
}

void Notification::setMessage(const std::string& msg) {
    if (message) {
        TrackedStringRegistry::instance().untrack(message);
        if (messageSize > 0) {
            SecureZeroMemory(message, messageSize);
        }
        TrackedStringRegistry::instance().deallocate(message);
    }

    messageSize = msg.size() + 1;
    message = static_cast<char*>(TrackedStringRegistry::instance().allocate(messageSize));
    if (message) {
        std::memcpy(message, msg.c_str(), messageSize);
        TrackedStringRegistry::instance().track(message, messageSize, true);
    }
}

void Notification::clearMessageAfterRender() {
    if (message && !rendered) {
        rendered = true;

        TrackedStringRegistry::instance().untrack(message);

        if (messageSize > 0) {
            SecureZeroMemory(message, messageSize);
        }

        TrackedStringRegistry::instance().deallocate(message);
        message = nullptr;
        messageSize = 0;
    }
}

NotificationModule::NotificationModule() = default;

NotificationModule::~NotificationModule() {
    clearAllNotifications();
}

void NotificationModule::removeExpiredNotifications() {
    auto currentTime = std::chrono::steady_clock::now();
    notifications.erase(
        std::ranges::remove_if(notifications,
                               [currentTime, this](Notification& notif) {
                                   if (notif.isEntering) return false;

                                   const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                       currentTime - notif.createTime
                                   ).count();

                                   return elapsed >= notificationLifetime + animationDuration &&
                                          notif.opacity <= 0.0f;
                               }
        ).begin(),
        notifications.end()
    );
}

float NotificationModule::calculateAnimationOffset(const Notification& notification) const {
    constexpr float offset = 100.0f;

    if (notification.isEntering) {
        const float progress = 1.0f - notification.opacity;

        switch (position) {
        case static_cast<int>(Position::TOP_LEFT):
        case static_cast<int>(Position::BOTTOM_LEFT):
            return -progress * offset;
        case static_cast<int>(Position::TOP_RIGHT):
        case static_cast<int>(Position::BOTTOM_RIGHT):
            return progress * offset;
        }
    }
    else {
        const float progress = 1.0f - notification.opacity;

        switch (position) {
        case static_cast<int>(Position::TOP_LEFT):
        case static_cast<int>(Position::BOTTOM_LEFT):
            return -progress * offset;
        case static_cast<int>(Position::TOP_RIGHT):
        case static_cast<int>(Position::BOTTOM_RIGHT):
            return progress * offset;
        }
    }

    return 0.0f;
}

void NotificationModule::updateNotificationAnimations() {
    const auto currentTime = std::chrono::steady_clock::now();

    for (auto& notification : notifications) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            currentTime - notification.createTime
        ).count() / 1000.0f;

        if (notification.isEntering) {
            notification.animationProgress = std::min(1.0f, elapsed / animationDuration);
            notification.opacity = notification.animationProgress;

            if (notification.animationProgress >= 1.0f) {
                notification.isEntering = false;
                notification.opacity = 1.0f;
                notification.createTime = currentTime;
            }
        }
        else {
            if (elapsed <= notificationLifetime) {
                notification.opacity = 1.0f;
                notification.animationProgress = 0.0f;
            }
            else {
                float fadeProgress = (elapsed - notificationLifetime) / animationDuration;
                notification.animationProgress = std::min(1.0f, fadeProgress);
                notification.opacity = 1.0f - notification.animationProgress;
            }
        }
    }
}

void NotificationModule::onUpdate() {
    removeExpiredNotifications();
    updateNotificationAnimations();

    if (notifications.capacity() > notifications.size() * 2 && notifications.capacity() > 10) {
        notifications.shrink_to_fit();
    }
}

void NotificationModule::putNofication(Notification& notification) {
    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState) return;

    if (!gameState->inGameHasFocus() && !gameState->isInventoryOpen()
        && !gameState->isChestOpen() && !gameState->isChatOpen()) {
        return;
    }

    notifications.emplace_back(std::move(notification));
}

void NotificationModule::addNotification(std::string moduleName, const bool enabled) {
    if (ConfigManager::getInstance().isLoadingConfig()) {
        secureErase(moduleName);
        return;
    }

    Notification notification;

    std::string msg = moduleName + " " + (enabled ? Strings::statusEnabled() : Strings::statusDisabled());
    secureErase(moduleName);
    notification.setMessage(msg);
    secureErase(msg);

    notification.color = enabled ? successColor : errorColor;
    notification.opacity = 0.0f;
    notification.createTime = std::chrono::steady_clock::now();
    notification.animationProgress = 0.0f;
    notification.isEntering = true;
    putNofication(notification);
}

void NotificationModule::addMessageNotification(std::string message, const ImColor color) {
    if (ConfigManager::getInstance().isLoadingConfig()) {
        secureErase(message);
        return;
    }

    Notification notification;
    notification.setMessage(message);
    secureErase(message);
    notification.color = color;
    notification.opacity = 0.0f;
    notification.createTime = std::chrono::steady_clock::now();
    notification.animationProgress = 0.0f;
    notification.isEntering = true;
    putNofication(notification);
}

void NotificationModule::addMessageNotificationForced(std::string message, const ImColor color) {
    Notification notification;
    notification.setMessage(message);
    secureErase(message);
    notification.color = color;
    notification.opacity = 0.0f;
    notification.createTime = std::chrono::steady_clock::now();
    notification.animationProgress = 0.0f;
    notification.isEntering = true;
    notifications.emplace_back(std::move(notification));
}

ImVec2 NotificationModule::calculateNotificationPosition(const float width, const float height, const float screenWidth,
                                                         const float screenHeight, const int index) const {
    float x = 0, y = 0;
    const float totalHeight = height + spacingY;

    switch (position) {
    case static_cast<int>(Position::TOP_LEFT):
        x = marginX;
        y = marginY + (index * totalHeight);
        break;
    case static_cast<int>(Position::TOP_RIGHT):
        x = screenWidth - width - marginX;
        y = marginY + (index * totalHeight);
        break;
    case static_cast<int>(Position::BOTTOM_LEFT):
        x = marginX;
        y = screenHeight - marginY - height - (index * totalHeight);
        break;
    case static_cast<int>(Position::BOTTOM_RIGHT):
        x = screenWidth - width - marginX;
        y = screenHeight - marginY - height - (index * totalHeight);
        break;
    }

    return { x, y };
}

void NotificationModule::addCustomNotification(std::string message, const ImColor color) {
    const auto notificationModule = ModuleHandler::getInstance().getModule<ModuleType::NOTIFICATION>();
    if (!notificationModule || !notificationModule->isEnabled()) {
        secureErase(message);
        return;
    }

    auto* notifModulePtr = static_cast<NotificationModule*>(notificationModule);
    notifModulePtr->addMessageNotification(std::move(message), color);
}

void NotificationModule::addModuleNotification(std::string moduleName, const bool enabled) {
    const auto notificationModule = ModuleHandler::getInstance().getModule<ModuleType::NOTIFICATION>();
    if (!notificationModule || !notificationModule->isEnabled()) {
        secureErase(moduleName);
        return;
    }

    auto* notifModulePtr = static_cast<NotificationModule*>(notificationModule);
    notifModulePtr->addNotification(std::move(moduleName), enabled);
}

void NotificationModule::clearAllNotifications() {
    notifications.clear();
    notifications.shrink_to_fit();
}

REGISTER_MODULE(NotificationModule, ModuleType::NOTIFICATION)
