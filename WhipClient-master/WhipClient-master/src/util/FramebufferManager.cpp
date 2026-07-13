#include "util/FramebufferManager.h"

typedef void (APIENTRY* PFNGLGENFRAMEBUFFERSPROC)(GLsizei n, GLuint* framebuffers);
typedef void (APIENTRY* PFNGLBINDFRAMEBUFFERPROC)(GLenum target, GLuint framebuffer);
typedef void (APIENTRY* PFNGLFRAMEBUFFERTEXTURE2DPROC)(GLenum target, GLenum attachment, GLenum textarget, GLuint texture, GLint level);
typedef void (APIENTRY* PFNGLGENRENDERBUFFERSPROC)(GLsizei n, GLuint* renderbuffers);
typedef void (APIENTRY* PFNGLBINDRENDERBUFFERPROC)(GLenum target, GLuint renderbuffer);
typedef void (APIENTRY* PFNGLRENDERBUFFERSTORAGEPROC)(GLenum target, GLenum internalformat, GLsizei width, GLsizei height);
typedef void (APIENTRY* PFNGLFRAMEBUFFERRENDERBUFFERPROC)(GLenum target, GLenum attachment, GLenum renderbuffertarget, GLuint renderbuffer);
typedef GLenum (APIENTRY* PFNGLCHECKFRAMEBUFFERSTATUSPROC)(GLenum target);
typedef void (APIENTRY* PFNGLDELETEFRAMEBUFFERSPROC)(GLsizei n, const GLuint* framebuffers);
typedef void (APIENTRY* PFNGLDELETERENDERBUFFERSPROC)(GLsizei n, const GLuint* renderbuffers);

static PFNGLGENFRAMEBUFFERSPROC glGenFramebuffers = nullptr;
static PFNGLBINDFRAMEBUFFERPROC glBindFramebuffer = nullptr;
static PFNGLFRAMEBUFFERTEXTURE2DPROC glFramebufferTexture2D = nullptr;
static PFNGLGENRENDERBUFFERSPROC glGenRenderbuffers = nullptr;
static PFNGLBINDRENDERBUFFERPROC glBindRenderbuffer = nullptr;
static PFNGLRENDERBUFFERSTORAGEPROC glRenderbufferStorage = nullptr;
static PFNGLFRAMEBUFFERRENDERBUFFERPROC glFramebufferRenderbuffer = nullptr;
static PFNGLCHECKFRAMEBUFFERSTATUSPROC glCheckFramebufferStatus = nullptr;
static PFNGLDELETEFRAMEBUFFERSPROC glDeleteFramebuffers = nullptr;
static PFNGLDELETERENDERBUFFERSPROC glDeleteRenderbuffers = nullptr;

static bool loadGLFunctions() {
    static bool loaded = false;
    if (loaded) return true;

    glGenFramebuffers = (PFNGLGENFRAMEBUFFERSPROC)wglGetProcAddress("glGenFramebuffers");
    glBindFramebuffer = (PFNGLBINDFRAMEBUFFERPROC)wglGetProcAddress("glBindFramebuffer");
    glFramebufferTexture2D = (PFNGLFRAMEBUFFERTEXTURE2DPROC)wglGetProcAddress("glFramebufferTexture2D");
    glGenRenderbuffers = (PFNGLGENRENDERBUFFERSPROC)wglGetProcAddress("glGenRenderbuffers");
    glBindRenderbuffer = (PFNGLBINDRENDERBUFFERPROC)wglGetProcAddress("glBindRenderbuffer");
    glRenderbufferStorage = (PFNGLRENDERBUFFERSTORAGEPROC)wglGetProcAddress("glRenderbufferStorage");
    glFramebufferRenderbuffer = (PFNGLFRAMEBUFFERRENDERBUFFERPROC)wglGetProcAddress("glFramebufferRenderbuffer");
    glCheckFramebufferStatus = (PFNGLCHECKFRAMEBUFFERSTATUSPROC)wglGetProcAddress("glCheckFramebufferStatus");
    glDeleteFramebuffers = (PFNGLDELETEFRAMEBUFFERSPROC)wglGetProcAddress("glDeleteFramebuffers");
    glDeleteRenderbuffers = (PFNGLDELETERENDERBUFFERSPROC)wglGetProcAddress("glDeleteRenderbuffers");

    loaded = (glGenFramebuffers && glBindFramebuffer && glFramebufferTexture2D &&
              glGenRenderbuffers && glBindRenderbuffer && glRenderbufferStorage &&
              glFramebufferRenderbuffer && glCheckFramebufferStatus &&
              glDeleteFramebuffers && glDeleteRenderbuffers);

    return loaded;
}

#define GL_FRAMEBUFFER 0x8D40
#define GL_RENDERBUFFER 0x8D41
#define GL_COLOR_ATTACHMENT0 0x8CE0
#define GL_DEPTH_STENCIL_ATTACHMENT 0x821A
#define GL_FRAMEBUFFER_COMPLETE 0x8CD5
#define GL_DEPTH24_STENCIL8 0x88F0
#define GL_CLAMP_TO_EDGE 0x812F
#define GL_RGBA8 0x8058

FramebufferManager::FramebufferManager()
    : sceneCaptureFBO(0), sceneCaptureTexture(0), sceneCaptureDepthRBO(0),
      width(0), height(0), initialized(false) {
    blurFBO[0] = blurFBO[1] = 0;
    blurTexture[0] = blurTexture[1] = 0;
}

FramebufferManager::~FramebufferManager() {
    cleanup();
}

void FramebufferManager::cleanup() {
    if (!loadGLFunctions()) return;

    if (sceneCaptureFBO) {
        glDeleteFramebuffers(1, &sceneCaptureFBO);
        sceneCaptureFBO = 0;
    }
    if (sceneCaptureTexture) {
        glDeleteTextures(1, &sceneCaptureTexture);
        sceneCaptureTexture = 0;
    }
    if (sceneCaptureDepthRBO) {
        glDeleteRenderbuffers(1, &sceneCaptureDepthRBO);
        sceneCaptureDepthRBO = 0;
    }

    for (int i = 0; i < 2; i++) {
        if (blurFBO[i]) {
            glDeleteFramebuffers(1, &blurFBO[i]);
            blurFBO[i] = 0;
        }
        if (blurTexture[i]) {
            glDeleteTextures(1, &blurTexture[i]);
            blurTexture[i] = 0;
        }
    }

    initialized = false;
}

bool FramebufferManager::checkFramebufferStatus(GLenum target) {
    if (!glCheckFramebufferStatus) return false;
    GLenum status = glCheckFramebufferStatus(target);
    return status == GL_FRAMEBUFFER_COMPLETE;
}

bool FramebufferManager::initialize(int w, int h) {
    if (!loadGLFunctions()) {
        return false;
    }

    cleanup();

    width = w;
    height = h;

    glGenFramebuffers(1, &sceneCaptureFBO);
    glBindFramebuffer(GL_FRAMEBUFFER, sceneCaptureFBO);

    glGenTextures(1, &sceneCaptureTexture);
    glBindTexture(GL_TEXTURE_2D, sceneCaptureTexture);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, sceneCaptureTexture, 0);

    glGenRenderbuffers(1, &sceneCaptureDepthRBO);
    glBindRenderbuffer(GL_RENDERBUFFER, sceneCaptureDepthRBO);
    glRenderbufferStorage(GL_RENDERBUFFER, GL_DEPTH24_STENCIL8, width, height);
    glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT, GL_RENDERBUFFER, sceneCaptureDepthRBO);

    if (!checkFramebufferStatus(GL_FRAMEBUFFER)) {
        cleanup();
        return false;
    }

    for (int i = 0; i < 2; i++) {
        glGenFramebuffers(1, &blurFBO[i]);
        glBindFramebuffer(GL_FRAMEBUFFER, blurFBO[i]);

        glGenTextures(1, &blurTexture[i]);
        glBindTexture(GL_TEXTURE_2D, blurTexture[i]);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, blurTexture[i], 0);

        if (!checkFramebufferStatus(GL_FRAMEBUFFER)) {
            cleanup();
            return false;
        }
    }

    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glBindTexture(GL_TEXTURE_2D, 0);
    glBindRenderbuffer(GL_RENDERBUFFER, 0);

    initialized = true;
    return true;
}

bool FramebufferManager::resize(int w, int h) {
    if (w == width && h == height) return true;
    return initialize(w, h);
}

void FramebufferManager::bindSceneCapture() {
    if (initialized && glBindFramebuffer) {
        glBindFramebuffer(GL_FRAMEBUFFER, sceneCaptureFBO);
    }
}

void FramebufferManager::unbindSceneCapture() {
    if (glBindFramebuffer) {
        glBindFramebuffer(GL_FRAMEBUFFER, 0);
    }
}
