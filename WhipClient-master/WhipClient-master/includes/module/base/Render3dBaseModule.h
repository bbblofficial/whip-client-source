#pragma once

#include "ListenedBaseModule.h"
#include "../../event/sub/Render3dEvent.h"
#include "util/RenderUtils.h"
#include <imgui.h>
#include <vector>
#include <string>
#include <array>
#include "GL.H"

template<typename Derived, ModuleType Type, CategoryType Category>
class Render3dBaseModule : public ListenedBaseModule<Derived, Type, Category> {
protected:

    using Vector3 = Vec3;
    using Vector2 = Vec2;
    using Vector4 = Vec4;

    enum class PlayerRelation : int { NEUTRAL = 0, FRIEND = 1, ENEMY = 2 };

    struct EnchantInfo {
        int id;
        int level;
    };

    struct PotionEffectInfo {
        int potionId;
        int duration;
        int amplifier;
    };

    struct PlayerData {
        Vector3 feetPosition;
        Vector3 position;
        std::string name;
        float health;
        float maxHealth;
        float distance;
        bool isValid;
        PlayerRelation relation = PlayerRelation::NEUTRAL;
        Vector3 boundingBox[8];
        jobject entityObject = nullptr;
        std::array<jobject, 4> armorItems = {nullptr, nullptr, nullptr, nullptr};
        std::array<int, 4> armorItemIds = {-1, -1, -1, -1};
        std::array<bool, 4> armorEnchanted = {false, false, false, false};
        std::array<std::vector<EnchantInfo>, 4> armorEnchantments;
        int heldItemId = -1;
        bool heldItemEnchanted = false;
        std::vector<EnchantInfo> heldItemEnchantments;
        jobject heldItemRef = nullptr;
        std::vector<PotionEffectInfo> potionEffects;
        float rotationYaw = 0.0f;
        float bodyYaw = 0.0f;
        float headYaw = 0.0f;
        float limbSwing = 0.0f;
        float limbSwingAmount = 0.0f;
        bool sneaking = false;
        int entityId = -1;
        int gappleCount = 0;

        PlayerData() : position(0, 0, 0), name(""), health(0), maxHealth(20), distance(0), isValid(false) {}
    };

public:
    explicit Render3dBaseModule(const BindType bindType = BindType::TOGGLE, const int keyCode = 0)
        : ListenedBaseModule<Derived, Type, Category>(bindType, keyCode) {
    }

    ~Render3dBaseModule() override = default;

protected:
    virtual void onRender3d(const Render3dEvent& event) = 0;

    void setupOpenGL();
    void setupOpenGL(const std::vector<float>& projectionMatrix, const std::vector<float>& modelViewMatrix);
    void restoreOpenGL();
    void setColor(const ImVec4& color);
    void drawLine3D(const Vector3& start, const Vector3& end);
    void drawQuad3D(const Vector3& v1, const Vector3& v2, const Vector3& v3, const Vector3& v4);
    void drawBox3D(const Vector3 corners[8], bool filled);
    void drawLine2D(const Vector2& start, const Vector2& end);
    void drawRect2D(const Vector2& topLeft, const Vector2& bottomRight, bool filled);

    void calculateBoundingBox(const Vector3& position, Vector3 boundingBox[8]);
    float calculateDistance(const Vector3& pos1, const Vector3& pos2);
    static Vector4 multiplyMatrixVector(const Vector4& vec, const std::vector<float>& matrix);
    bool worldToScreen(const Vector3 &worldPos, Vector2 &screenPos, const std::vector<float> &projectionMatrix, const std::vector<float> &
                       modelViewMatrix, bool behind = false) const;
    [[nodiscard]] ImVec4 interpolateColor(const ImVec4& color1, const ImVec4& color2, float factor) const;
    bool isBoxVisible(const Vector3 boundingBox[8], const std::vector<float>& projectionMatrix, const std::vector<float>& modelViewMatrix) const;
    void registerEvents() override {
        this->template subscribe<Render3dEvent>([this](const Render3dEvent& event) {
            if (this->isEnabled()) {
                onRender3d(event);
            }
        });
    }
};

template<typename Derived, ModuleType Type, CategoryType Category>
void Render3dBaseModule<Derived, Type, Category>::setupOpenGL() {
    RenderUtils::setupOpenGL();
}

template<typename Derived, ModuleType Type, CategoryType Category>
void Render3dBaseModule<Derived, Type, Category>::setupOpenGL(const std::vector<float>& projectionMatrix, const std::vector<float>& modelViewMatrix) {
    RenderUtils::setupOpenGL(projectionMatrix, modelViewMatrix);
}

template<typename Derived, ModuleType Type, CategoryType Category>
void Render3dBaseModule<Derived, Type, Category>::restoreOpenGL() {
    RenderUtils::restoreOpenGLState();
}

template<typename Derived, ModuleType Type, CategoryType Category>
void Render3dBaseModule<Derived, Type, Category>::setColor(const ImVec4& color) {
    RenderUtils::setColor(color);
}

template<typename Derived, ModuleType Type, CategoryType Category>
void Render3dBaseModule<Derived, Type, Category>::drawLine3D(const Vector3& start, const Vector3& end) {
    RenderUtils::drawLine3D(start, end);
}

template<typename Derived, ModuleType Type, CategoryType Category>
void Render3dBaseModule<Derived, Type, Category>::drawQuad3D(const Vector3& v1, const Vector3& v2, const Vector3& v3, const Vector3& v4) {
    RenderUtils::drawQuad3D(v1, v2, v3, v4);
}

template<typename Derived, ModuleType Type, CategoryType Category>
void Render3dBaseModule<Derived, Type, Category>::drawBox3D(const Vector3 corners[8], bool filled) {
    RenderUtils::drawBox3D(corners, filled);
}

template<typename Derived, ModuleType Type, CategoryType Category>
void Render3dBaseModule<Derived, Type, Category>::drawLine2D(const Vector2& start, const Vector2& end) {
    RenderUtils::drawLine2D(start, end);
}

template<typename Derived, ModuleType Type, CategoryType Category>
void Render3dBaseModule<Derived, Type, Category>::drawRect2D(const Vector2& topLeft, const Vector2& bottomRight, bool filled) {
    RenderUtils::drawRect2D(topLeft, bottomRight, filled);
}

template<typename Derived, ModuleType Type, CategoryType Category>
bool Render3dBaseModule<Derived, Type, Category>::worldToScreen(const Vector3& worldPos, Vector2& screenPos, const std::vector<float>& projectionMatrix, const std::vector<float>& modelViewMatrix, bool behind) const {
    return RenderUtils::worldToScreen(worldPos, screenPos, projectionMatrix, modelViewMatrix, behind);
}

template<typename Derived, ModuleType Type, CategoryType Category>
ImVec4 Render3dBaseModule<Derived, Type, Category>::interpolateColor(const ImVec4& color1, const ImVec4& color2, float factor) const {
    return RenderUtils::interpolateColor(color1, color2, factor);
}

template<typename Derived, ModuleType Type, CategoryType Category>
typename Render3dBaseModule<Derived, Type, Category>::Vector4
Render3dBaseModule<Derived, Type, Category>::multiplyMatrixVector(const Vector4& vec, const std::vector<float>& matrix) {
    return RenderUtils::multiplyMatrixVector(vec, matrix);
}

template<typename Derived, ModuleType Type, CategoryType Category>
void Render3dBaseModule<Derived, Type, Category>::calculateBoundingBox(const Vector3& position, Vector3 boundingBox[8]) {
    RenderUtils::calculateBoundingBox(position, boundingBox);
}

template<typename Derived, ModuleType Type, CategoryType Category>
float Render3dBaseModule<Derived, Type, Category>::calculateDistance(const Vector3& pos1, const Vector3& pos2) {
    return RenderUtils::calculateDistance(pos1, pos2);
}

template<typename Derived, ModuleType Type, CategoryType Category>
bool Render3dBaseModule<Derived, Type, Category>::isBoxVisible(const Vector3 boundingBox[8], const std::vector<float>& projectionMatrix, const std::vector<float>& modelViewMatrix) const {
    return RenderUtils::isBoxVisible(boundingBox, projectionMatrix, modelViewMatrix);
}
