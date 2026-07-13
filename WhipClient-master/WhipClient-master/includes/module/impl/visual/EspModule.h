#pragma once

#include "../../base/PlayerDataRender3dBaseModule.h"
#include <imgui.h>
#include <string>

#include "../setting/EnemiesModule.h"
#include "../setting/FriendsModule.h"
#include "util/ClientStrings.h"

class ESPModule final : public PlayerDataRender3dBaseModule<ESPModule, ModuleType::ESP, CategoryType::VISUAL> {
    int renderMode = 1;
    int mode3d = 2;
    int mode2d = 2;

    bool showHealthBar = true;
    bool showHearts = false;
    bool showArmor = false;
    bool showEnemiesOnly = false;
    bool hideFriends = false;
    float maxRenderDistance = 64.0f;

    EnemiesModule* enemiesModule = nullptr;
    FriendsModule* friendsModule = nullptr;

    ImColor outline3dColor = ImColor(1.0f, 0.0f, 0.0f, 1.0f);
    ImColor fill3dColor = ImColor(1.0f, 0.0f, 0.0f, 0.3f);
    float fill3dOpacity = 0.3f;
    ImColor outline2dColor = ImColor(0.0f, 1.0f, 0.0f, 1.0f);
    ImColor fill2dColor = ImColor(0.0f, 1.0f, 0.0f, 0.2f);
    ImColor friendColor = ImColor(0.0f, 1.0f, 0.0f, 1.0f);
    ImColor neutralColor = ImColor(1.0f, 1.0f, 1.0f, 1.0f);
    ImColor healthBarBg = ImColor(0.2f, 0.2f, 0.2f, 0.8f);
    ImColor healthBarFull = ImColor(0.0f, 1.0f, 0.0f, 1.0f);
    ImColor healthBarLow = ImColor(1.0f, 0.0f, 0.0f, 1.0f);

    float outline3dWidth = 2.0f;
    float outline2dWidth = 1.5f;
    float healthBarWidth = 3.0f;
    float healthBarHeight = 30.0f;
    float healthBarOffset = 5.0f;

    void drawHealthBar2D(const Vector2& pos, float boxHeight, float health, float maxHealth);
    void drawHearts2D(JNIEnv* env, const Vector2& topLeft, float boxWidth, float boxHeight, float distance, float health, float maxHealth);
    void drawArmor2D(JNIEnv* env, const Vector2& topLeft, float boxWidth, float boxHeight, float distance, const std::array<jobject, 4>& armorItems);
    bool worldToScreen(const Vector3& worldPos, Vector2& screenPos);

    bool updateMatrices(JNIEnv *env);

    void collectPlayerData(JNIEnv *env);

    static float calculateSmoothScale(float distance, float minDist = 3.0f, float maxDist = 25.0f, float minScale = 0.6f, float maxScale = 1.8f);
public:
    explicit ESPModule(BindType bindType = BindType::TOGGLE, int keyCode = 0);

    void onRender3d(const Render3dEvent& event) override;

    void onLoad() override {
        PlayerDataRender3dBaseModule::onLoad();

        COMBO_SETTING(renderMode, Strings::render2D(), Strings::render3D(), Strings::renderBoth());

        COMBO_SETTING_OPTIONAL(mode3d, SETTING_VISIBILITY(renderMode == 1 || renderMode == 2), Strings::renderOutline(), Strings::renderFill(), Strings::renderBoth());
        COLOR_SETTING_CONDITIONAL_OPTIONAL(outline3dColor, ImColor(1.0f, 0.0f, 0.0f, 1.0f), SETTING_VISIBILITY((renderMode == 1 || renderMode == 2) && (mode3d == 0 || mode3d == 2)));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(fill3dColor, ImColor(1.0f, 0.0f, 0.0f, 1.0f), SETTING_VISIBILITY((renderMode == 1 || renderMode == 2) && (mode3d == 1 || mode3d == 2)));
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(fill3dOpacity, 0.3f, 0.0f, 1.0f, SETTING_VISIBILITY((renderMode == 1 || renderMode == 2) && (mode3d == 1 || mode3d == 2)));
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(outline3dWidth, 2.0f, 0.5f, 5.0f, SETTING_VISIBILITY((renderMode == 1 || renderMode == 2) && (mode3d == 0 || mode3d == 2)));

        COMBO_SETTING_OPTIONAL(mode2d, SETTING_VISIBILITY(renderMode == 0 || renderMode == 2), Strings::renderOutline(), Strings::renderFill(), Strings::renderBoth());

        BOOL_SETTING_CONDITIONAL_OPTIONAL(showHealthBar, true, SETTING_VISIBILITY(renderMode == 0 || renderMode == 2));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(healthBarBg, ImColor(0.2f, 0.2f, 0.2f, 0.8f), SETTING_VISIBILITY((renderMode == 0 || renderMode == 2) && showHealthBar));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(healthBarFull, ImColor(0.0f, 1.0f, 0.0f, 1.0f), SETTING_VISIBILITY((renderMode == 0 || renderMode == 2) && showHealthBar));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(healthBarLow, ImColor(1.0f, 0.0f, 0.0f, 1.0f), SETTING_VISIBILITY((renderMode == 0 || renderMode == 2) && showHealthBar));
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(healthBarWidth, 3.0f, 1.0f, 10.0f, SETTING_VISIBILITY((renderMode == 0 || renderMode == 2) && showHealthBar));
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(healthBarOffset, 5.0f, 0.0f, 20.0f, SETTING_VISIBILITY((renderMode == 0 || renderMode == 2) && showHealthBar));

        BOOL_SETTING_CONDITIONAL(showHearts, false);

        BOOL_SETTING_CONDITIONAL(showEnemiesOnly, false);
        BOOL_SETTING_CONDITIONAL(hideFriends, false);
        COLOR_SETTING(friendColor, ImColor(0.0f, 1.0f, 0.0f, 1.0f));
        COLOR_SETTING(neutralColor, ImColor(1.0f, 1.0f, 1.0f, 1.0f));

        COLOR_SETTING_CONDITIONAL_OPTIONAL(outline2dColor, ImColor(0.0f, 1.0f, 0.0f, 1.0f), SETTING_VISIBILITY((renderMode == 0 || renderMode == 2) && (mode2d == 0 || mode2d == 2)));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(fill2dColor, ImColor(0.0f, 1.0f, 0.0f, 0.2f), SETTING_VISIBILITY((renderMode == 0 || renderMode == 2) && (mode2d == 1 || mode2d == 2)));
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(outline2dWidth, 1.5f, 0.5f, 3.0f, SETTING_VISIBILITY((renderMode == 0 || renderMode == 2) && (mode2d == 0 || mode2d == 2)));

        FLOAT_SLIDER_CONDITIONAL(maxRenderDistance, 64.0f, 16.0f, 128.0f);
    }
};
