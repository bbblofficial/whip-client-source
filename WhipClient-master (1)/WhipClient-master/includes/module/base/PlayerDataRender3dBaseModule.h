#pragma once

#include "Render3dBaseModule.h"
#include "../../event/sub/RenderWorldEvent.h"
#include <vector>

template<typename Derived, ModuleType Type, CategoryType Category>
class PlayerDataRender3dBaseModule : public Render3dBaseModule<Derived, Type, Category> {
protected:
    std::vector<typename Render3dBaseModule<Derived, Type, Category>::PlayerData> players;
    typename Render3dBaseModule<Derived, Type, Category>::Vector3 localPlayerPos;

    std::vector<float> projectionMatrix;
    std::vector<float> modelViewMatrix;
    float maxRenderDistance = 64.0f;

public:
    PlayerDataRender3dBaseModule(const BindType bindType = BindType::TOGGLE, const int keyCode = 0)
        : Render3dBaseModule<Derived, Type, Category>(bindType, keyCode) {
        projectionMatrix.resize(16, 0.0f);
        modelViewMatrix.resize(16, 0.0f);
    }

    ~PlayerDataRender3dBaseModule() override = default;

protected:

    void registerEvents() override {
        Render3dBaseModule<Derived, Type, Category>::registerEvents();
    }

    virtual void updateMatricesImpl() {}
    virtual void collectPlayerDataImpl() {}
};
