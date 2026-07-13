#pragma once

#include "../base/BaseHUDElement.h"
#include "../renderer/ArraylistEntry.h"
#include "../../module/impl/visual/ArrayListModule.h"
#include <imgui.h>

#include "Poppins-Bold.h"
#include "Poppins-SemiBold.h"

class ArraylistHUDElement final : public BaseHUDElement {
    ArrayListModule* config;

    mutable char sharedFlagsBuffer[64];

    static constexpr float BASE_LINE_SPACING = 2.0f;
    static constexpr float BASE_FONT_SIZE = 22.0f;
    static constexpr float TITLE_SCALE = 1.2f;
    static constexpr float BASE_SHADOW_OFFSET = 1.5f;
    static constexpr float BASE_BAR_WIDTH = 2.45f;
    static constexpr float BASE_ROUNDING = 3.0f;
    static constexpr float MAX_SCALE = 3.0f;

    float currentScale_ = -1.0f;
    bool resizing_ = false;
    float resizeBaseScale_ = 0.0f;
    float resizeBaseMouseX_ = 0.0f;

    ImFont* cachedTitleFont = nullptr;
    ImFont* cachedHudFont   = nullptr;
    bool fontsInitialized = false;

public:
    explicit ArraylistHUDElement();
    ~ArraylistHUDElement() override = default;

    void onInit() override {
    }

protected:
    void onRender() override;

    void initializeFonts();

    bool ensureFontsValid();

    void drawTextWithShadow(ImDrawList* drawList, const ImFont* font, float fontSize, const ImVec2& pos,
                            const ImColor& color, const char* text) const;
};
