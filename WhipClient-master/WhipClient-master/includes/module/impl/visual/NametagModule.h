#pragma once

#include "../../base/PlayerDataRender3dBaseModule.h"
#include "../../event/sub/RenderNameEvent.h"
#include <imgui.h>
#include <string>
#include <unordered_map>

#include "../setting/EnemiesModule.h"
#include "../setting/FriendsModule.h"
#include "util/ClientStrings.h"
#include "wrapper/minecraft/client/texture/TextureManager.h"

class NametagModule final : public PlayerDataRender3dBaseModule<NametagModule, ModuleType::NAMETAG, CategoryType::VISUAL> {

    struct TextSegment {
        std::string text;
        ImVec4 color;
    };

    bool showNames = true;
    bool showHealth = true;
    bool showDistance = true;
    bool showBackground = true;
    bool showHealthBar = true;
    bool showOutline = true;
    bool showEnemiesOnly = false;
    bool hideFriends = false;
    float nametagScale = 0.6f;
    float textSize = 8.0f;
    float outlineThickness = 1.0f;
    float maxRenderDistance = 64.0f;

    float healthBarWidth = 50.0f;
    float healthBarHeight = 4.0f;

    ImColor friendColor = ImColor(0.0f, 1.0f, 0.0f, 1.0f);
    ImColor neutralColor = ImColor(1.0f, 1.0f, 1.0f, 1.0f);
    ImColor nameColor = ImColor(1.0f, 1.0f, 1.0f, 1.0f);
    ImColor healthColor = ImColor(0.0f, 1.0f, 0.0f, 1.0f);
    ImColor distanceColor = ImColor(0.8f, 0.8f, 0.8f, 1.0f);
    ImColor backgroundColor = ImColor(0.0f, 0.0f, 0.0f, 0.2f);
    ImColor healthBarBg = ImColor(0.2f, 0.2f, 0.2f, 0.8f);
    ImColor healthBarFull = ImColor(0.0f, 1.0f, 0.0f, 1.0f);
    ImColor healthBarLow = ImColor(1.0f, 0.0f, 0.0f, 1.0f);
    ImColor outlineColor = ImColor(0.0f, 0.0f, 0.0f, 1.0f);

    EnemiesModule* enemiesModule = nullptr;
    FriendsModule* friendsModule = nullptr;

    std::unordered_map<float, ImFont*> cachedFonts;
    bool fontsInitialized = false;

    void initializeFonts();
    ImFont* getOrCreateFont(float size);

    void drawTextWithOutline(const char *text, const Vector2 & pos, const ImVec4 &color, float size, bool centered);
    void drawHealthBar(const Vector2& pos, float health, float maxHealth, float width, float height);
    void drawHearts2D(const Vector2& center, float scaleFactor, float health, float maxHealth);
    void drawArmor2D(JNIEnv* env, TextureManager& textureManager, const Vector2& center, float scaleFactor, const std::array<jobject, 4>& armorItems);
    void onRenderName(const RenderNameEvent& event);

    bool worldToScreen(const Vector3 & worldPos, Vector2 & screenPos);

    bool updateMatrices(JNIEnv *env);

    ImVec4 minecraftColorToImVec4(char code);

    std::vector<TextSegment> parseMinecraftText(const std::string& text);

    void drawColoredText(const std::vector<TextSegment>& segments, const Vector2& pos, float size, bool centered);

public:
    explicit NametagModule(BindType bindType = BindType::TOGGLE, int keyCode = 0);

    void collectPlayerData(JNIEnv *env);

    void onRender3d(const Render3dEvent& event) override;

    void registerEvents() override;

    void onLoad() override {
        PlayerDataRender3dBaseModule::onLoad();

        BOOL_SETTING_CONDITIONAL(showNames, true);
        BOOL_SETTING_CONDITIONAL(showHealth, true);
        BOOL_SETTING_CONDITIONAL(showDistance, true);
        BOOL_SETTING_CONDITIONAL(showBackground, true);
        BOOL_SETTING_CONDITIONAL(showEnemiesOnly, false);
        BOOL_SETTING_CONDITIONAL(hideFriends, false);
        COLOR_SETTING(friendColor, ImColor(0.0f, 1.0f, 0.0f, 1.0f));
        COLOR_SETTING(neutralColor, ImColor(1.0f, 1.0f, 1.0f, 1.0f));

        COLOR_SETTING_OPTIONAL(nameColor, ImColor(1.0f, 1.0f, 1.0f, 1.0f), SETTING_VISIBILITY(showNames));
        COLOR_SETTING_OPTIONAL(backgroundColor, ImColor(0.0f, 0.0f, 0.0f, 0.2f), SETTING_VISIBILITY(showBackground));

        FLOAT_SLIDER_CONDITIONAL(nametagScale, 1.0f, 0.1f, 3.0f);
        FLOAT_SLIDER_CONDITIONAL(maxRenderDistance, 64.0f, 16.0f, 128.0f);
    }
};
