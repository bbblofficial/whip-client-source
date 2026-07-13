#pragma once

#include "../../base/Render3dBaseModule.h"
#include "../../../setting/SettingMacros.h"
#include <imgui.h>
#include <vector>

struct TrajectoryPoint {
    float x, y, z;
};

struct HitEntityBox {
    bool valid = false;
    double minX, minY, minZ;
    double maxX, maxY, maxZ;
};

enum class ProjectileType {
    NONE, SNOWBALL, EGG, BOW, ENDER_PEARL, POTION, ROD
};

class TrajectoriesModule final
    : public Render3dBaseModule<TrajectoriesModule, ModuleType::TRAJECTORIES, CategoryType::VISUAL> {
    friend class BaseModule;

    float lineWidth = 2.0f;
    ImColor arcColor = ImColor(0.08f, 0.47f, 0.90f, 0.85f);

    std::vector<bool> projectileFilter = {true, true, true, true, true, true};

    std::vector<TrajectoryPoint> points_;
    HitEntityBox hitEntity_;

    void onRender3d(const Render3dEvent& event) override;

public:
    explicit TrajectoriesModule(BindType bindType = BindType::TOGGLE, int keyCode = 0);

    void onLoad() override;
    void onEnable() override;
    void onDisable() override;

    static TrajectoriesModule* getInstancePtr() {
        return &BaseModule::getInstance();
    }
};
