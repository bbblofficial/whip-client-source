#pragma once

#include "../../base/PlayerDataRender3dBaseModule.h"
#include <imgui.h>
#include <string>

#include "util/xor.h"
#include "util/ClientStrings.h"

class StorageESPModule final : public PlayerDataRender3dBaseModule<StorageESPModule, ModuleType::STORAGE_ESP, CategoryType::VISUAL> {
    int renderMode = 2;
    int mode3d = 0;
    int mode2d = 2;

    std::vector<bool> selectedStorageTypes;

    float maxRenderDistance = 64.0f;

    ImColor chestColor = ImColor(1.0f, 0.84f, 0.0f, 1.0f);
    ImColor enderChestColor = ImColor(0.5f, 0.0f, 0.5f, 1.0f);
    ImColor trappedChestColor = ImColor(1.0f, 0.0f, 0.0f, 1.0f);
    ImColor furnaceColor = ImColor(0.5f, 0.5f, 0.5f, 1.0f);
    ImColor dispenserColor = ImColor(0.3f, 0.3f, 0.3f, 1.0f);
    ImColor dropperColor = ImColor(0.4f, 0.4f, 0.4f, 1.0f);
    ImColor hopperColor = ImColor(0.2f, 0.2f, 0.2f, 1.0f);

    float outline3dWidth = 2.0f;
    float outline2dWidth = 1.5f;
    float fillAlpha3d = 0.15f;
    float fillAlpha2d = 0.25f;

    bool showLabels = true;
    ImColor labelColor = ImColor(1.0f, 1.0f, 1.0f, 1.0f);
    float labelScale = 1.0f;

    bool worldToScreen(const Vector3& worldPos, Vector2& screenPos);
    bool updateMatrices(JNIEnv* env);
    void collectPlayerData(JNIEnv* env);

    ImColor getStorageColor(const std::string& type);
    std::string getStorageLabel(const std::string& type);
    bool isStorageTypeEnabled(const std::string& type);

public:
    explicit StorageESPModule(BindType bindType = BindType::TOGGLE, int keyCode = 0);

    void onRender3d(const Render3dEvent& event) override;

    void onLoad() override {
        PlayerDataRender3dBaseModule::onLoad();

        COMBO_SETTING(renderMode, Strings::render2D(), Strings::render3D(), Strings::renderBoth());

        COMBO_SETTING_OPTIONAL(mode3d, SETTING_VISIBILITY(renderMode == 1 || renderMode == 2), Strings::renderOutline(), Strings::renderFill(), Strings::renderBoth());
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(outline3dWidth, 2.0f, 0.5f, 5.0f, SETTING_VISIBILITY((renderMode == 1 || renderMode == 2) && (mode3d == 0 || mode3d == 2)));

        COMBO_SETTING_OPTIONAL(mode2d, SETTING_VISIBILITY(renderMode == 0 || renderMode == 2), Strings::renderOutline(), Strings::renderFill(), Strings::renderBoth());
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(outline2dWidth, 1.5f, 0.5f, 3.0f, SETTING_VISIBILITY((renderMode == 0 || renderMode == 2) && (mode2d == 0 || mode2d == 2)));
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(fillAlpha2d, 0.25f, 0.0f, 1.0f, SETTING_VISIBILITY((renderMode == 0 || renderMode == 2) && (mode2d == 1 || mode2d == 2)));

        MULTI_COMBO_SETTING(selectedStorageTypes, Strings::storageChest(), Strings::storageEnderChest(), Strings::storageTrappedChest(), Strings::storageFurnace(), Strings::storageDispenser(), Strings::storageDropper(), Strings::storageHopper());

        COLOR_SETTING_CONDITIONAL_OPTIONAL(chestColor, ImColor(1.0f, 0.84f, 0.0f, 1.0f), SETTING_VISIBILITY(selectedStorageTypes.size() > 0 && selectedStorageTypes[0]));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(enderChestColor, ImColor(0.5f, 0.0f, 0.5f, 1.0f), SETTING_VISIBILITY(selectedStorageTypes.size() > 1 && selectedStorageTypes[1]));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(trappedChestColor, ImColor(1.0f, 0.0f, 0.0f, 1.0f), SETTING_VISIBILITY(selectedStorageTypes.size() > 2 && selectedStorageTypes[2]));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(furnaceColor, ImColor(0.5f, 0.5f, 0.5f, 1.0f), SETTING_VISIBILITY(selectedStorageTypes.size() > 3 && selectedStorageTypes[3]));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(dispenserColor, ImColor(0.3f, 0.3f, 0.3f, 1.0f), SETTING_VISIBILITY(selectedStorageTypes.size() > 4 && selectedStorageTypes[4]));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(dropperColor, ImColor(0.4f, 0.4f, 0.4f, 1.0f), SETTING_VISIBILITY(selectedStorageTypes.size() > 5 && selectedStorageTypes[5]));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(hopperColor, ImColor(0.2f, 0.2f, 0.2f, 1.0f), SETTING_VISIBILITY(selectedStorageTypes.size() > 6 && selectedStorageTypes[6]));
    }
};
