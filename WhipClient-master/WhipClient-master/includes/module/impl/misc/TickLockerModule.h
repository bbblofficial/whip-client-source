#pragma once

#include "../../../hud/renderer/IArraylistRenderer.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../event/sub/MouseBlockClickEvent.h"
#include "../../../util/JniScope.h"
#include "wrapper/minecraft/util/movingobjectposition.h"
#include <imgui.h>
#include <windows.h>

#include "event/sub/Render3dEvent.h"
#include "module/base/DedicatedThreadBaseModule.h"
#include "util/xor.h"
#include "util/ClientStrings.h"
#include "util/MathUtils.h"

class TickLockerModule final : public DedicatedThreadBaseModule<TickLockerModule, ModuleType::TICK_LOCKER, CategoryType::MISC> {
    static constexpr auto SET_COLOR = ImColor(255, 87, 87, 255);

    bool isBlocking = false;
    bool isRightClickHeld = false;
    int targetBlockPosKey = 0;
    bool targetBlockPosKeyWasPress = false;
    bool cancelLeftClick = false;
    int mode = 0;

    std::vector<Vec3> blockBoundingBox;

    std::string targetBlockText = "Target: None";
    float blockDamagePercent = 0.0f;

protected:
    void onUpdate(JniScope& scope) override;
    void registerEvents() override;

public:
    MovingObjectPosition::position targetBlockPos;
    bool showOutline = true;
    bool showFill = true;
    bool renderSelectedBlock = false;
    ImColor outlineColor = ImColor(1.0f, 0.0f, 0.0f, 1.0f);
    ImColor fillColor = ImColor(1.0f, 0.0f, 0.0f, 0.3f);
    float outlineWidth = 2.0f;

    TickLockerModule() = default;
    ~TickLockerModule() override;

    void onEnable() override {
        DedicatedThreadBaseModule::onEnable();
    }

    void onDisable() override {
        DedicatedThreadBaseModule::onDisable();
        resetTargetBlock();
    }

    void onCleanup() override { clearInstanceBuffer(); }

    void onLoad() override {
        DedicatedThreadBaseModule::onLoad();

        COMBO_SETTING(mode, Strings::modeLegit(), Strings::modeBlatant());
        BUTTON_SETTING(Strings::btnClear(), [this] {
            resetTargetBlock();
        });

        KEYBIND_SETTING_CONDITIONAL(targetBlockPosKey, 0);

        BOOL_SETTING_CONDITIONAL(renderSelectedBlock, false);
        BOOL_SETTING_CONDITIONAL_OPTIONAL(showOutline, true, SETTING_VISIBILITY(renderSelectedBlock));
        BOOL_SETTING_CONDITIONAL_OPTIONAL(showFill, false, SETTING_VISIBILITY(renderSelectedBlock));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(outlineColor, ImColor(1.0f, 0.0f, 0.0f, 1.0f), SETTING_VISIBILITY(showOutline));
        COLOR_SETTING_CONDITIONAL_OPTIONAL(fillColor, ImColor(1.0f, 0.0f, 0.0f, 0.3f), SETTING_VISIBILITY(showFill));
        FLOAT_SLIDER_CONDITIONAL_OPTIONAL(outlineWidth, 2.0f, 0.5f, 5.0f, SETTING_VISIBILITY(showOutline));
    }

    void resetTargetBlock() {
        const bool wasBlocking = isBlocking;
        const bool hadTarget = (targetBlockPos.x != 0 || targetBlockPos.y != 0 || targetBlockPos.z != 0);
        targetBlockPos = {};
        blockDamagePercent = 0.0f;
        if (isBlocking) {
            cancelLeftClick = false;
            if (isRightClickHeld && mode == 0) {
                releaseRightClick();
            }
            isBlocking = false;
        }
        targetBlockPosKeyWasPress = false;
        if (wasBlocking || hadTarget) {
            NotificationModule::addCustomNotification(Strings::msgTargetBlockCleared(), SET_COLOR);
        }
    }

    void onMouseLeftClick(const MouseBlockClickEvent& eventt);

    void onRender3d(const Render3dEvent& event);

    void calculateBlockBoundingBox(const MovingObjectPosition::position& blockPos) {
        blockBoundingBox.clear();

        const float x = static_cast<float>(blockPos.x);
        const float y = static_cast<float>(blockPos.y);
        const float z = static_cast<float>(blockPos.z);

        blockBoundingBox.push_back(Vec3(x, y, z));
        blockBoundingBox.push_back(Vec3(x + 1, y, z));
        blockBoundingBox.push_back(Vec3(x + 1, y, z + 1));
        blockBoundingBox.push_back(Vec3(x, y, z + 1));
        blockBoundingBox.push_back(Vec3(x, y + 1, z));
        blockBoundingBox.push_back(Vec3(x + 1, y + 1, z));
        blockBoundingBox.push_back(Vec3(x + 1, y + 1, z + 1));
        blockBoundingBox.push_back(Vec3(x, y + 1, z + 1));
    }

private:
	mutable char instanceBuffer[64] = {0};

public:

    FORMAT_FLAGS("%s %.1f", (this->mode == 0 ? Strings::modeLegit() : Strings::modeBlatant()), this->blockDamagePercent)

private:
    void holdRightClick();
    void releaseRightClick();
};
