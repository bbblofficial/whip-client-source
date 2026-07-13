#pragma once

#include "../../base/Render3dBaseModule.h"
#include "../setting/FriendsModule.h"
#include "../setting/EnemiesModule.h"
#include <imgui.h>
#include <vector>

class ChamsModule final
    : public Render3dBaseModule<ChamsModule, ModuleType::CHAMS, CategoryType::VISUAL> {
    friend class BaseModule;

    std::vector<bool> entitiesFilter = {true, true, true, true, true, false};

    bool renderTexture = false;
    bool glowMode = false;
    bool hideFriends = false;
    FriendsModule* friendsModule = nullptr;
    EnemiesModule* enemiesModule = nullptr;

    ImColor colorFriend = ImColor(0.0f, 1.0f, 0.0f, 0.39f);
    ImColor colorNeutral = ImColor(1.0f, 1.0f, 1.0f, 0.39f);

    void onRender3d(const Render3dEvent& event) override;

public:

    static inline bool isRenderingChams = false;

    explicit ChamsModule(BindType bindType = BindType::TOGGLE, int keyCode = 0);

    void onLoad() override;
    void onEnable() override;
    void onDisable() override;

    static ChamsModule* getInstancePtr() {
        return &BaseModule::getInstance();
    }

    bool isGlowMode() const { return glowMode; }
    bool isRenderTexture() const { return renderTexture; }
    bool isHideFriends() const { return hideFriends; }

    void getColorForEntity(JNIEnv* env, jobject entityObj, float outColor[4]) const;
    bool passesEntityFilter(JNIEnv* env, jobject entityObj) const;

    void renderChamsOverlay(JNIEnv* env);
};
