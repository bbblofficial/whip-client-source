#pragma once

#include <Windows.h>
#include <gl/GL.h>

class FramebufferManager {
private:
    GLuint sceneCaptureFBO;
    GLuint sceneCaptureTexture;
    GLuint sceneCaptureDepthRBO;

    GLuint blurFBO[2];
    GLuint blurTexture[2];

    int width;
    int height;
    bool initialized;

    bool checkFramebufferStatus(GLenum target);

public:
    void cleanup();
    FramebufferManager();
    ~FramebufferManager();

    bool initialize(int width, int height);
    bool resize(int width, int height);

    void bindSceneCapture();
    void unbindSceneCapture();

    GLuint getSceneCaptureFBO() const { return sceneCaptureFBO; }
    GLuint getSceneCaptureTexture() const { return sceneCaptureTexture; }
    GLuint getBlurFBO(int index) const { return blurFBO[index]; }
    GLuint getBlurTexture(int index) const { return blurTexture[index]; }

    bool isInitialized() const { return initialized; }
};
