#pragma once

#include "../../base/PlayerDataRender3dBaseModule.h"
#include <imgui.h>
#include <string>
#include <vector>
#include <unordered_map>

#include "../setting/EnemiesModule.h"
#include "../setting/FriendsModule.h"
#include "wrapper/minecraft/enchantment/EnchantmentHelper.h"

class PlayerESPModule final : public PlayerDataRender3dBaseModule<PlayerESPModule, ModuleType::PLAYER_ESP, CategoryType::VISUAL> {

    std::vector<bool> features = {true, true, true, true, true, true, true};
    bool showArmor = true;
    bool showPotionEffects = true;
    bool showHeldItem = true;
    bool showSkeleton = true;
    bool showOutline = true;
    bool showGappleCount = true;
    bool unifyWithNametag = true;

    std::unordered_map<int, int> gappleCounts;

    bool outlineGlow = false;
    int outlineMode = 0;
    float displayScale = 1.5f;
    float skeletonThickness = 1.5f;
    float outlineThickness = 1.5f;
    float outlineGlowRadius = 6.0f;
    ImColor skeletonColor = ImColor(1.0f, 1.0f, 1.0f, 1.0f);
    ImColor outlineColor = ImColor(1.0f, 1.0f, 1.0f, 1.0f);
    float maxRenderDistance = 64.0f;

    EnemiesModule* enemiesModule = nullptr;
    FriendsModule* friendsModule = nullptr;

    std::unordered_map<float, ImFont*> cachedFonts;
    bool fontsInitialized = false;

    void initializeFonts();
    ImFont* getOrCreateFont(float size);

    void collectPlayerData(JNIEnv* env);
    bool worldToScreen(const Vector3& worldPos, Vector2& screenPos);
    bool updateMatrices(JNIEnv* env);

    static const char* getItemTexturePath(int itemId);
    static const char* getEnchantAbbrev(int enchId);

    void renderArmorColumn(JNIEnv* env, ImDrawList* drawList,
                           float centerX, float nametagTopY, float scaleFactor,
                           float minWidth, const PlayerData& player);
    void renderPotionColumn(JNIEnv* env, ImDrawList* drawList, float centerX, float armorTopY,
                            float scaleFactor, float minWidth, const PlayerData& player);
    void renderSkeleton(ImDrawList* drawList, const PlayerData& player);
    void renderOutline(ImDrawList* drawList, const PlayerData& player);

public:

    static inline std::unordered_map<int, float> sharedBlockW;

    void renderOutlineOverlay(JNIEnv* env);

    static inline bool isRenderingOutline = false;

    static PlayerESPModule* getInstancePtr() {
        return &BaseModule::getInstance();
    }

private:

    static std::string formatDuration(int ticks);

public:
    explicit PlayerESPModule(BindType bindType = BindType::TOGGLE, int keyCode = 0);

    void onRender3d(const Render3dEvent& event) override;

    void onLoad() override {
        PlayerDataRender3dBaseModule::onLoad();
        MULTI_COMBO_SETTING(features, "Armor", "Potions", "Held Item", "Skeleton", "Outline", "Gapple", "Unify Nametag");
        COMBO_SETTING_OPTIONAL(outlineMode, SETTING_VISIBILITY(showOutline), "3D", "2D");
        BOOL_SETTING_CONDITIONAL_OPTIONAL(outlineGlow, false, SETTING_VISIBILITY(showOutline));
        FLOAT_SLIDER_CONDITIONAL(displayScale, 1.5f, 0.5f, 3.0f);
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(skeletonThickness, 1.5f, 0.5f, 5.0f, SETTING_VISIBILITY(showSkeleton));
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(outlineThickness, 1.5f, 0.5f, 5.0f, SETTING_VISIBILITY(showOutline));
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(outlineGlowRadius, 6.0f, 1.0f, 20.0f, SETTING_VISIBILITY(showOutline && outlineGlow));
        COLOR_SETTING_OPTIONAL(skeletonColor, ImColor(1.0f, 1.0f, 1.0f, 1.0f), SETTING_VISIBILITY(showSkeleton));
        COLOR_SETTING_OPTIONAL(outlineColor, ImColor(1.0f, 1.0f, 1.0f, 1.0f), SETTING_VISIBILITY(showOutline));
        FLOAT_SLIDER_CONDITIONAL(maxRenderDistance, 64.0f, 16.0f, 128.0f);
    }
};
