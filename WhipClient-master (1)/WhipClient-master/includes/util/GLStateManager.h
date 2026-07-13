#pragma once

#include <Windows.h>
#include <gl/GL.h>

class GLStateManager {
private:
    struct GLState {
        GLint activeTexture;
        GLint currentProgram;
        GLint textureBinding2D;
        GLint vertexArrayBinding;
        GLint framebufferBinding;
        GLboolean blendEnabled;
        GLint blendSrcRGB;
        GLint blendDstRGB;
        GLint blendSrcAlpha;
        GLint blendDstAlpha;
        GLboolean depthTestEnabled;
        GLboolean cullFaceEnabled;
        GLboolean scissorTestEnabled;
        GLint viewport[4];
    } savedState;

public:
    GLStateManager() = default;
    ~GLStateManager() = default;

    void save();
    void restore();
};
