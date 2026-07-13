#pragma once

#include <Windows.h>

#include "GL.H"

class BlurRenderer {
private:
    GLuint blurShaderProgram;
    GLuint quadShaderProgram;

    GLuint quadVAO;
    GLuint quadVBO;

    GLint blurImageLoc;
    GLint blurRadiusLoc;
    GLint blurDirectionLoc;
    GLint quadTextureLoc;
    GLint quadAlphaLoc;
    GLint quadProjectionLoc;

    bool initialized;
    float blurRadius;

    bool compileShader(GLuint* shader, GLenum type, const char* source);
    bool linkProgram(GLuint program);
    void setupQuadGeometry();

public:
    BlurRenderer();
    ~BlurRenderer();

    bool initialize();
    void shutdown();

    void setBlurRadius(float radius) { blurRadius = radius; }
    float getBlurRadius() const { return blurRadius; }

    void performBlurPass(GLuint inputTexture, GLuint outputFBO,
                        bool horizontal, int width, int height);

    void renderBlurredQuad(GLuint blurredTexture,
                          float x, float y, float width, float height,
                          float screenWidth, float screenHeight,
                          float alpha = 1.0f);

    bool isInitialized() const { return initialized; }
};
