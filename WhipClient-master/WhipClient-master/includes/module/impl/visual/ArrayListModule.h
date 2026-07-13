#pragma once

#include "../../base/SharedThreadBaseModule.h"
#include "../../hud/renderer/ArraylistEntry.h"
#include "util/ClientStrings.h"
#include <vector>

class ArrayListModule final : public SharedThreadBaseModule<ArrayListModule, ModuleType::ARRAYLIST, CategoryType::VISUAL> {
public:
    enum ColorMode {
        STATIC = 0,
        RAINBOW = 1,
        FADE = 2,
        FLOW = 3,
        GUI_BASED = 4
    };

    inline static int colorMode = STATIC;
    inline static auto mainColor = ImColor(65, 105, 225, 255);
    inline static auto shadowColor = ImColor(0, 0, 0, 255);
    inline static auto delayColor = ImColor(255, 255, 255, 140);
    inline static auto flowColor = ImColor(70, 132, 255, 255);
    inline static auto moduleBoxColor = ImColor(15, 15, 18, 200);

    inline static bool showTitle = false;
    inline static bool titleCustomColor = false;
    inline static int titleColorMode = STATIC;
    inline static auto titleMainColor = ImColor(65, 105, 225, 255);
    inline static auto titleFlowColor = ImColor(70, 132, 255, 255);

    inline static bool fadeReversed = false;
    inline static bool shadowEnabled = true;
    inline static bool drawBox = true;
    inline static bool bar = true;
    inline static bool textShadows = true;
    inline static bool lowerCase = false;
    inline static bool blurEnabled = true;
    inline static float blurOpacity = 0.90f;
    inline static bool glowEnabled = false;
    inline static float glowSize = 30.0f;
    inline static float glowAlpha = 1.0f;

    inline static float paddingX = 5.0f;
    inline static float paddingY = 2.0f;

    inline static float posNX    = 1.0f;
    inline static float posNY    = 0.0f;
    inline static float scale    = 1.0f;

    ArrayListModule();
    void onUpdate(JniScope& scope) override;

    void onLoad() override {
        SharedThreadBaseModule::onLoad();

        COMBO_SETTING(colorMode, Strings::optStatic(), "Rainbow", "Fade", "Flow", "GUI Based");
        COLOR_SETTING_OPTIONAL(mainColor, ImColor(65, 105, 225, 255), SETTING_VISIBILITY(colorMode == STATIC || colorMode == FADE));
        COLOR_SETTING_OPTIONAL(flowColor, ImColor(70, 132, 255, 255), SETTING_VISIBILITY(colorMode == FLOW));
        BOOL_SETTING_CONDITIONAL_OPTIONAL(fadeReversed, false, SETTING_VISIBILITY(colorMode == FADE));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(delayColor, ImColor(255, 255, 255, 140), SETTING_VISIBILITY(colorMode != GUI_BASED));

        BOOL_SETTING_CONDITIONAL_OPTIONAL(showTitle, false, SETTING_VISIBILITY(colorMode != GUI_BASED));
        BOOL_SETTING_CONDITIONAL_OPTIONAL(titleCustomColor, false, SETTING_VISIBILITY(colorMode != GUI_BASED && showTitle));
        COMBO_SETTING_CONDITIONAL_OPTIONAL(titleColorMode, SETTING_VISIBILITY(colorMode != GUI_BASED && showTitle && titleCustomColor), Strings::optStatic(), "Rainbow", "Flow");
        COLOR_SETTING_CONDITIONAL_OPTIONAL(titleMainColor, ImColor(65, 105, 225, 255), SETTING_VISIBILITY(colorMode != GUI_BASED && showTitle && titleCustomColor && titleColorMode == 0));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(titleFlowColor, ImColor(70, 132, 255, 255), SETTING_VISIBILITY(colorMode != GUI_BASED && showTitle && titleCustomColor && titleColorMode == 2));

        BOOL_SETTING_CONDITIONAL(textShadows, true);
        BOOL_SETTING_CONDITIONAL_OPTIONAL(drawBox, true, SETTING_VISIBILITY(colorMode != GUI_BASED));
        BOOL_SETTING_CONDITIONAL(blurEnabled, true);
        FLOAT_SLIDER(blurOpacity, 0.90f, 0.0f, 1.0f);
        BOOL_SETTING_CONDITIONAL_OPTIONAL(glowEnabled, false, SETTING_VISIBILITY(colorMode != GUI_BASED));
        BOOL_SETTING_CONDITIONAL(lowerCase, false);
        BOOL_SETTING_CONDITIONAL(bar, true);
        FLOAT_SLIDER(scale, 1.0f, 0.5f, 3.0f);
        REGISTER_FLOAT(posNX, 1.0f);
        REGISTER_FLOAT(posNY, 0.0f);

    }

    [[nodiscard]] bool shouldShowInArraylist() const override {
        return false;
    }

    void setEnabled(const bool enabled) override {
        NotificationModule::addModuleNotification(Strings::modArrayList(), enabled);
        setEnabled2(enabled);
    }

    [[nodiscard]] std::vector<ArraylistEntry> getCalculatedEntries() const;

private:
    std::vector<ArraylistEntry> calculatedEntries;

    std::vector<ArraylistEntry> collectNewSystemModules();
    void sortEntriesByWidth(std::vector<ArraylistEntry>& entries);
};
