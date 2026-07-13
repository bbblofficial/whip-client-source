#include "util/RenderUtils.h"

#include <algorithm>

#include "GL.H"

typedef unsigned int GLenum;
typedef unsigned char GLboolean;
typedef int GLint;
typedef float GLfloat;
typedef double GLdouble;

#define GL_MODELVIEW                      0x1700
#define GL_PROJECTION                     0x1701
#define GL_LINE_SMOOTH                    0x0B20
#define GL_LINE_SMOOTH_HINT               0x0C52
#define GL_NICEST                         0x1102
#define GL_DEPTH_TEST                     0x0B71
#define GL_TEXTURE_2D                     0x0DE1
#define GL_BLEND                          0x0BE2
#define GL_SRC_ALPHA                      0x0302
#define GL_ONE_MINUS_SRC_ALPHA            0x0303
#define GL_ONE                            1
#define GL_QUADS                          0x0007
#define GL_LINE_LOOP                      0x0002
#define GL_LINES                          0x0001
#define GL_BLEND_SRC                      0x0BE1
#define GL_BLEND_DST                      0x0BE0
#define GL_TRUE                           1
#define GL_FALSE                          0

#pragma comment(lib, "opengl32.lib")

void RenderUtils::setupRenderState(float lineWidth) {
    glPushMatrix();
    glEnable(GL_LINE_SMOOTH);
    glHint(GL_LINE_SMOOTH_HINT, GL_NICEST);
    glDisable(GL_DEPTH_TEST);
    glDisable(GL_TEXTURE_2D);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glEnable(GL_BLEND);
    glLineWidth(lineWidth);
}

void RenderUtils::restoreRenderState() {
    glDisable(GL_BLEND);
    glEnable(GL_TEXTURE_2D);
    glEnable(GL_DEPTH_TEST);
    glDisable(GL_LINE_SMOOTH);
    glPopMatrix();
}

void RenderUtils::draw3DBox(const Vector3f& min, const Vector3f& max, const Color& color, bool filled, bool outlined) {
    if (filled) drawBoxFilled(min, max, color);
    if (outlined) drawBoxLines(min, max, color);
}

void RenderUtils::draw2DBox(float x1, float y1, float x2, float y2, const Color& color, bool filled, bool outlined) {
    if (filled) draw2DBoxFilled(x1, y1, x2, y2, color);
    if (outlined) draw2DBoxLines(x1, y1, x2, y2, color);
}

void RenderUtils::drawBoxFilled(const Vector3f& min, const Vector3f& max, const Color& color) {
    glColor4f(color.r, color.g, color.b, color.a * 0.3f);
    glBegin(GL_QUADS);
    glVertex3f(min.x, min.y, min.z); glVertex3f(min.x, max.y, min.z);
    glVertex3f(max.x, max.y, min.z); glVertex3f(max.x, min.y, min.z);
    glVertex3f(max.x, min.y, max.z); glVertex3f(max.x, max.y, max.z);
    glVertex3f(min.x, max.y, max.z); glVertex3f(min.x, min.y, max.z);
    glVertex3f(min.x, min.y, min.z); glVertex3f(min.x, min.y, max.z);
    glVertex3f(min.x, max.y, max.z); glVertex3f(min.x, max.y, min.z);
    glVertex3f(max.x, min.y, max.z); glVertex3f(max.x, min.y, min.z);
    glVertex3f(max.x, max.y, min.z); glVertex3f(max.x, max.y, max.z);
    glVertex3f(min.x, min.y, min.z); glVertex3f(max.x, min.y, min.z);
    glVertex3f(max.x, min.y, max.z); glVertex3f(min.x, min.y, max.z);
    glVertex3f(min.x, max.y, max.z); glVertex3f(max.x, max.y, max.z);
    glVertex3f(max.x, max.y, min.z); glVertex3f(min.x, max.y, min.z);
    glEnd();
}

void RenderUtils::drawBoxLines(const Vector3f& min, const Vector3f& max, const Color& color) {
    glColor4f(color.r, color.g, color.b, color.a);
    glBegin(GL_LINE_LOOP);
    glVertex3f(min.x, min.y, min.z); glVertex3f(max.x, min.y, min.z);
    glVertex3f(max.x, min.y, max.z); glVertex3f(min.x, min.y, max.z);
    glEnd();
    glBegin(GL_LINE_LOOP);
    glVertex3f(min.x, max.y, min.z); glVertex3f(max.x, max.y, min.z);
    glVertex3f(max.x, max.y, max.z); glVertex3f(min.x, max.y, max.z);
    glEnd();
    glBegin(GL_LINES);
    glVertex3f(min.x, min.y, min.z); glVertex3f(min.x, max.y, min.z);
    glVertex3f(max.x, min.y, min.z); glVertex3f(max.x, max.y, min.z);
    glVertex3f(max.x, min.y, max.z); glVertex3f(max.x, max.y, max.z);
    glVertex3f(min.x, min.y, max.z); glVertex3f(min.x, max.y, max.z);
    glEnd();
}

void RenderUtils::draw2DBoxFilled(float x1, float y1, float x2, float y2, const Color& color) {
    glColor4f(color.r, color.g, color.b, color.a * 0.3f);
    glBegin(GL_QUADS);
    glVertex2f(x1, y1); glVertex2f(x2, y1);
    glVertex2f(x2, y2); glVertex2f(x1, y2);
    glEnd();
}

void RenderUtils::draw2DBoxLines(float x1, float y1, float x2, float y2, const Color& color) {
    glColor4f(color.r, color.g, color.b, color.a);
    glBegin(GL_LINE_LOOP);
    glVertex2f(x1, y1); glVertex2f(x2, y1);
    glVertex2f(x2, y2); glVertex2f(x1, y2);
    glEnd();
}

void RenderUtils::drawGlowingBox(const Vector3f& min, const Vector3f& max, const Color& color) {
    GLint oldBlendSrc, oldBlendDst;
    glGetIntegerv(GL_BLEND_SRC, &oldBlendSrc);
    glGetIntegerv(GL_BLEND_DST, &oldBlendDst);

    glBlendFunc(GL_SRC_ALPHA, GL_ONE);
    glDepthMask(GL_FALSE);

    for (int i = 0; i < 5; i++) {
        float expansion = 0.05f + (i * 0.03f);
        float alpha = (1.0f - (i * 0.15f)) * 0.8f;
        float brightness = 1.2f - (i * 0.1f);

        Color glowColor(
            std::min(color.r * brightness, 1.0f),
            std::min(color.g * brightness, 1.0f),
            std::min(color.b * brightness, 1.0f),
            alpha
        );

        Vector3f expandedMin(min.x - expansion, min.y - expansion, min.z - expansion);
        Vector3f expandedMax(max.x + expansion, max.y + expansion, max.z + expansion);

        drawBoxFilled(expandedMin, expandedMax, glowColor);
        if (i < 3) {
            glowColor.a = alpha * 1.5f;
            drawBoxLines(expandedMin, expandedMax, glowColor);
        }
    }

    Color coreColor(
        std::min(color.r * 1.5f, 1.0f),
        std::min(color.g * 1.5f, 1.0f),
        std::min(color.b * 1.5f, 1.0f),
        0.9f
    );
    drawBoxFilled(min, max, coreColor);
    drawBoxLines(min, max, coreColor);

    glDepthMask(GL_TRUE);
    glBlendFunc(oldBlendSrc, oldBlendDst);
}

void RenderUtils::setupOpenGL() {
    glPushAttrib(GL_ALL_ATTRIB_BITS);
    glPushMatrix();

    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glDisable(GL_TEXTURE_2D);
    glDisable(GL_DEPTH_TEST);
    glDepthMask(GL_FALSE);

    glLineWidth(1.0f);
}

void RenderUtils::setupOpenGL(const std::vector<float>& projectionMatrix, const std::vector<float>& modelViewMatrix) {
    glPushAttrib(GL_ALL_ATTRIB_BITS);
    glPushMatrix();

    const ImGuiIO& io = ImGui::GetIO();
    glViewport(0, 0, static_cast<int>(io.DisplaySize.x), static_cast<int>(io.DisplaySize.y));

    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    if (projectionMatrix.size() == 16) {
        glLoadMatrixf(projectionMatrix.data());
    }

    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();
    if (modelViewMatrix.size() == 16) {
        glLoadMatrixf(modelViewMatrix.data());
    }

    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glEnable(GL_LINE_SMOOTH);
    glHint(GL_LINE_SMOOTH_HINT, GL_NICEST);
    glDisable(GL_DEPTH_TEST);
    glDisable(GL_LIGHTING);
    glDisable(GL_TEXTURE_2D);
    glDisable(GL_CULL_FACE);
}

void RenderUtils::restoreOpenGLState() {
    glMatrixMode(GL_PROJECTION);
    glPopMatrix();
    glMatrixMode(GL_MODELVIEW);
    glPopMatrix();
    glPopMatrix();
    glPopAttrib();
}

void RenderUtils::setColor(const ImVec4& color) {
    glColor4f(color.x, color.y, color.z, color.w);
}

void RenderUtils::drawLine3D(const Vec3& start, const Vec3& end) {
    glBegin(GL_LINES);
    glVertex3f(start.x, start.y, start.z);
    glVertex3f(end.x, end.y, end.z);
    glEnd();
}

void RenderUtils::drawQuad3D(const Vec3& v1, const Vec3& v2, const Vec3& v3, const Vec3& v4) {
    glBegin(GL_QUADS);
    glVertex3f(v1.x, v1.y, v1.z);
    glVertex3f(v2.x, v2.y, v2.z);
    glVertex3f(v3.x, v3.y, v3.z);
    glVertex3f(v4.x, v4.y, v4.z);
    glEnd();
}

void RenderUtils::drawBox3D(const Vec3 corners[8], bool filled) {
    if (filled) {
        glBegin(GL_QUADS);

        glVertex3f(corners[0].x, corners[0].y, corners[0].z);
        glVertex3f(corners[1].x, corners[1].y, corners[1].z);
        glVertex3f(corners[5].x, corners[5].y, corners[5].z);
        glVertex3f(corners[4].x, corners[4].y, corners[4].z);

        glVertex3f(corners[2].x, corners[2].y, corners[2].z);
        glVertex3f(corners[6].x, corners[6].y, corners[6].z);
        glVertex3f(corners[7].x, corners[7].y, corners[7].z);
        glVertex3f(corners[3].x, corners[3].y, corners[3].z);

        glVertex3f(corners[4].x, corners[4].y, corners[4].z);
        glVertex3f(corners[5].x, corners[5].y, corners[5].z);
        glVertex3f(corners[6].x, corners[6].y, corners[6].z);
        glVertex3f(corners[7].x, corners[7].y, corners[7].z);

        glVertex3f(corners[0].x, corners[0].y, corners[0].z);
        glVertex3f(corners[3].x, corners[3].y, corners[3].z);
        glVertex3f(corners[2].x, corners[2].y, corners[2].z);
        glVertex3f(corners[1].x, corners[1].y, corners[1].z);

        glVertex3f(corners[1].x, corners[1].y, corners[1].z);
        glVertex3f(corners[2].x, corners[2].y, corners[2].z);
        glVertex3f(corners[6].x, corners[6].y, corners[6].z);
        glVertex3f(corners[5].x, corners[5].y, corners[5].z);

        glVertex3f(corners[0].x, corners[0].y, corners[0].z);
        glVertex3f(corners[4].x, corners[4].y, corners[4].z);
        glVertex3f(corners[7].x, corners[7].y, corners[7].z);
        glVertex3f(corners[3].x, corners[3].y, corners[3].z);

        glEnd();
    } else {
        glBegin(GL_LINES);

        glVertex3f(corners[0].x, corners[0].y, corners[0].z); glVertex3f(corners[1].x, corners[1].y, corners[1].z);
        glVertex3f(corners[1].x, corners[1].y, corners[1].z); glVertex3f(corners[2].x, corners[2].y, corners[2].z);
        glVertex3f(corners[2].x, corners[2].y, corners[2].z); glVertex3f(corners[3].x, corners[3].y, corners[3].z);
        glVertex3f(corners[3].x, corners[3].y, corners[3].z); glVertex3f(corners[0].x, corners[0].y, corners[0].z);

        glVertex3f(corners[4].x, corners[4].y, corners[4].z); glVertex3f(corners[5].x, corners[5].y, corners[5].z);
        glVertex3f(corners[5].x, corners[5].y, corners[5].z); glVertex3f(corners[6].x, corners[6].y, corners[6].z);
        glVertex3f(corners[6].x, corners[6].y, corners[6].z); glVertex3f(corners[7].x, corners[7].y, corners[7].z);
        glVertex3f(corners[7].x, corners[7].y, corners[7].z); glVertex3f(corners[4].x, corners[4].y, corners[4].z);

        glVertex3f(corners[0].x, corners[0].y, corners[0].z); glVertex3f(corners[4].x, corners[4].y, corners[4].z);
        glVertex3f(corners[1].x, corners[1].y, corners[1].z); glVertex3f(corners[5].x, corners[5].y, corners[5].z);
        glVertex3f(corners[2].x, corners[2].y, corners[2].z); glVertex3f(corners[6].x, corners[6].y, corners[6].z);
        glVertex3f(corners[3].x, corners[3].y, corners[3].z); glVertex3f(corners[7].x, corners[7].y, corners[7].z);

        glEnd();
    }
}

void RenderUtils::drawLine2D(const Vec2& start, const Vec2& end) {
    glBegin(GL_LINES);
    glVertex2f(start.x, start.y);
    glVertex2f(end.x, end.y);
    glEnd();
}

void RenderUtils::drawRect2D(const Vec2& topLeft, const Vec2& bottomRight, bool filled) {
    if (filled) {
        glBegin(GL_QUADS);
        glVertex2f(topLeft.x, topLeft.y);
        glVertex2f(bottomRight.x, topLeft.y);
        glVertex2f(bottomRight.x, bottomRight.y);
        glVertex2f(topLeft.x, bottomRight.y);
        glEnd();
    } else {
        glBegin(GL_LINE_LOOP);
        glVertex2f(topLeft.x, topLeft.y);
        glVertex2f(bottomRight.x, topLeft.y);
        glVertex2f(bottomRight.x, bottomRight.y);
        glVertex2f(topLeft.x, bottomRight.y);
        glEnd();
    }
}

void RenderUtils::calculateBoundingBox(const Vec3& position, Vec3 boundingBox[8]) {
    constexpr float width = 0.6f;
    float height = 1.8f;
    float halfWidth = width * 0.5f;

    boundingBox[0] = Vec3(position.x - halfWidth, position.y, position.z - halfWidth);
    boundingBox[1] = Vec3(position.x + halfWidth, position.y, position.z - halfWidth);
    boundingBox[2] = Vec3(position.x + halfWidth, position.y, position.z + halfWidth);
    boundingBox[3] = Vec3(position.x - halfWidth, position.y, position.z + halfWidth);

    boundingBox[4] = Vec3(position.x - halfWidth, position.y + height, position.z - halfWidth);
    boundingBox[5] = Vec3(position.x + halfWidth, position.y + height, position.z - halfWidth);
    boundingBox[6] = Vec3(position.x + halfWidth, position.y + height, position.z + halfWidth);
    boundingBox[7] = Vec3(position.x - halfWidth, position.y + height, position.z + halfWidth);
}

float RenderUtils::calculateDistance(const Vec3& pos1, const Vec3& pos2) {
    const float dx = pos1.x - pos2.x;
    const float dy = pos1.y - pos2.y;
    const float dz = pos1.z - pos2.z;
    return std::sqrt(dx * dx + dy * dy + dz * dz);
}

Vec4 RenderUtils::multiplyMatrixVector(const Vec4& vec, const std::vector<float>& matrix) {
    if (matrix.size() != 16) return Vec4(0, 0, 0, 0);

    return Vec4(
        vec.x * matrix[0] + vec.y * matrix[4] + vec.z * matrix[8] + vec.w * matrix[12],
        vec.x * matrix[1] + vec.y * matrix[5] + vec.z * matrix[9] + vec.w * matrix[13],
        vec.x * matrix[2] + vec.y * matrix[6] + vec.z * matrix[10] + vec.w * matrix[14],
        vec.x * matrix[3] + vec.y * matrix[7] + vec.z * matrix[11] + vec.w * matrix[15]
    );
}

bool RenderUtils::worldToScreen(const Vec3& worldPos, Vec2& screenPos, const std::vector<float>& projectionMatrix,
                                const std::vector<float>& modelViewMatrix, bool behind) {
    if (projectionMatrix.size() != 16 || modelViewMatrix.size() != 16) {
        return false;
    }

    Vec4 clipPos = multiplyMatrixVector(
        multiplyMatrixVector(Vec4(worldPos.x, worldPos.y, worldPos.z, 1.0f), modelViewMatrix),
        projectionMatrix
    );

    if (behind) {
        bool isBehind = clipPos.w < 0.0f;

        if (clipPos.w == 0.0f) return false;

        Vec3 ndcPos(clipPos.x / clipPos.w, clipPos.y / clipPos.w, clipPos.z / clipPos.w);

        if (isBehind) {
            ndcPos.x = -ndcPos.x;
            ndcPos.y = -ndcPos.y;
        }

        GLint viewport[4];
        glGetIntegerv(GL_VIEWPORT, viewport);

        screenPos.x = (ndcPos.x + 1.0f) * 0.5f * viewport[2] + viewport[0];
        screenPos.y = (1.0f - ndcPos.y) * 0.5f * viewport[3] + viewport[1];
    } else {
        if (clipPos.w == 0.0f) return false;

        Vec3 ndcPos(clipPos.x / clipPos.w, clipPos.y / clipPos.w, clipPos.z / clipPos.w);

        if (ndcPos.z < -1.0f || ndcPos.z > 1.0f) return false;

        GLint viewport[4];
        glGetIntegerv(GL_VIEWPORT, viewport);

        screenPos.x = (ndcPos.x + 1.0f) * 0.5f * viewport[2] + viewport[0];
        screenPos.y = (1.0f - ndcPos.y) * 0.5f * viewport[3] + viewport[1];
    }
    return true;
}

ImVec4 RenderUtils::interpolateColor(const ImVec4& color1, const ImVec4& color2, float factor) {
    factor = std::max(0.0f, std::min(1.0f, factor));

    return {
        color1.x + (color2.x - color1.x) * factor,
        color1.y + (color2.y - color1.y) * factor,
        color1.z + (color2.z - color1.z) * factor,
        color1.w + (color2.w - color1.w) * factor
    };
}

bool RenderUtils::isBoxVisible(const Vec3 boundingBox[8], const std::vector<float>& projectionMatrix,
                               const std::vector<float>& modelViewMatrix) {
    for (int i = 0; i < 8; i++) {
        Vec2 screenPos;
        if (worldToScreen(boundingBox[i], screenPos, projectionMatrix, modelViewMatrix)) {
            return true;
        }
    }
    return false;
}
