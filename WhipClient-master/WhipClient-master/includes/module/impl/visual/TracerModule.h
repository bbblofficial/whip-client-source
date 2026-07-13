#pragma once

#include "../../base/PlayerDataRender3dBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include <string>
#include <imgui.h>
#include "module/impl/setting/EnemiesModule.h"
#include "module/impl/setting/FriendsModule.h"
#include "util/ClientStrings.h"

class TracerModule final : public PlayerDataRender3dBaseModule<TracerModule, ModuleType::TRACER, CategoryType::VISUAL> {
    bool enableTracers = true;
    bool showHealthInfo = false;
    bool showEnemiesOnly = false;
    bool hideFriends = false;

    bool traceAllPlayers = true;
    float maxRenderDistance = 64.0f;

    ImColor tracerColor = ImColor(1.0f, 0.0f, 0.0f, 1.0f);
    ImColor friendColor = ImColor(0.0f, 1.0f, 0.0f, 1.0f);
    ImColor neutralColor = ImColor(1.0f, 1.0f, 1.0f, 1.0f);
    ImColor healthBarBg = ImColor(0.2f, 0.2f, 0.2f, 0.8f);
    ImColor healthBarFull = ImColor(0.0f, 1.0f, 0.0f, 1.0f);
    ImColor healthBarLow = ImColor(1.0f, 0.0f, 0.0f, 1.0f);

    float tracerWidth = 2.0f;
    float healthBarWidth = 3.0f;
    float healthBarHeight = 30.0f;
    float healthBarOffset = 5.0f;

    EnemiesModule* enemiesModule = nullptr;
    FriendsModule* friendsModule = nullptr;

    bool isPlayerBehindCamera(const Vector3& playerPos, const Vector3& cameraPos, const Vector3& cameraLookAt);
    void drawHealthBar2D(const Vector2& pos, float health, float maxHealth);
    bool worldToScreen(const Vector3& worldPos, Vector2& screenPos);
    bool updateMatrices(JNIEnv *env);
    void collectPlayerData(JNIEnv *env);

public:
    explicit TracerModule(BindType bindType = BindType::TOGGLE, int keyCode = 0);

    void onRender3d(const Render3dEvent& event) override;

    void onLoad() override {
        PlayerDataRender3dBaseModule::onLoad();

        BOOL_SETTING_CONDITIONAL(showEnemiesOnly, false);
        BOOL_SETTING_CONDITIONAL(hideFriends, false);

        COLOR_SETTING_OPTIONAL(tracerColor, ImColor(1.0f, 0.0f, 0.0f, 1.0f), SETTING_VISIBILITY(enableTracers));
        COLOR_SETTING(friendColor, ImColor(0.0f, 1.0f, 0.0f, 1.0f));
        COLOR_SETTING(neutralColor, ImColor(1.0f, 1.0f, 1.0f, 1.0f));
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(tracerWidth, 2.0f, 0.5f, 5.0f, SETTING_VISIBILITY(enableTracers));
        FLOAT_SLIDER_CONDITIONAL(maxRenderDistance, 64.0f, 16.0f, 128.0f);
    }
};
