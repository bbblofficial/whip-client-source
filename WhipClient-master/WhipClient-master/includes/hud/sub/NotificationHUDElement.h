#pragma once

#include "../base/BaseHUDElement.h"
#include "../../module/impl/visual/NotificationModule.h"
#include <imgui.h>
#include <unordered_map>

#include "Poppins-SemiBold.h"

class NotificationHUDElement final : public BaseHUDElement {
    NotificationModule* config;

    const float NOTIFICATION_HEIGHT = 30.0f;
    const float NOTIFICATION_PADDING = 10.0f;
    const float NOTIFICATION_MARGIN = 5.0f;
    const float BASE_FONT_SIZE = 16.0f;
    const float SHADOW_OFFSET = 1.0f;
    const float ROUNDING = 5.0f;

    std::unordered_map<float, ImFont*> cachedFonts;
    bool fontsInitialized = false;

    bool resizing_ = false;
    float resizeBaseScale_ = 0.0f;
    float resizeBaseMouseX_ = 0.0f;

public:
    explicit NotificationHUDElement();
    ~NotificationHUDElement() override = default;

    void onInit() override {
    }

protected:
    void onRender() override;
    void initializeFonts();
    ImFont* getOrCreateFont(float size);
};
