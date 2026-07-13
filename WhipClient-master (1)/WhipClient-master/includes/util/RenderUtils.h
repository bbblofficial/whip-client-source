#pragma once
#include "MathUtils.h"
#include <imgui.h>
#include <vector>
#include <GL.H>

class RenderUtils {
public:

    static void draw3DBox(const Vector3f& min, const Vector3f& max, const Color& color, bool filled, bool outlined);
    static void draw2DBox(float x1, float y1, float x2, float y2, const Color& color, bool filled, bool outlined);
    static void drawBoxFilled(const Vector3f& min, const Vector3f& max, const Color& color);
    static void drawBoxLines(const Vector3f& min, const Vector3f& max, const Color& color);
    static void draw2DBoxFilled(float x1, float y1, float x2, float y2, const Color& color);
    static void draw2DBoxLines(float x1, float y1, float x2, float y2, const Color& color);
    static void drawGlowingBox(const Vector3f& min, const Vector3f& max, const Color& color);

    static void setupRenderState(float lineWidth);
    static void restoreRenderState();

    static void setupOpenGL();
    static void setupOpenGL(const std::vector<float>& projectionMatrix, const std::vector<float>& modelViewMatrix);
    static void restoreOpenGLState();
    static void setColor(const ImVec4& color);
    static void drawLine3D(const Vec3& start, const Vec3& end);
    static void drawQuad3D(const Vec3& v1, const Vec3& v2, const Vec3& v3, const Vec3& v4);
    static void drawBox3D(const Vec3 corners[8], bool filled);
    static void drawLine2D(const Vec2& start, const Vec2& end);
    static void drawRect2D(const Vec2& topLeft, const Vec2& bottomRight, bool filled);

    static void calculateBoundingBox(const Vec3& position, Vec3 boundingBox[8]);
    static float calculateDistance(const Vec3& pos1, const Vec3& pos2);
    static Vec4 multiplyMatrixVector(const Vec4& vec, const std::vector<float>& matrix);
    static bool worldToScreen(const Vec3& worldPos, Vec2& screenPos, const std::vector<float>& projectionMatrix,
                             const std::vector<float>& modelViewMatrix, bool behind = false);
    static ImVec4 interpolateColor(const ImVec4& color1, const ImVec4& color2, float factor);
    static bool isBoxVisible(const Vec3 boundingBox[8], const std::vector<float>& projectionMatrix,
                            const std::vector<float>& modelViewMatrix);
};
