#include "util/GLStateManager.h"

#ifndef GL_ACTIVE_TEXTURE
#define GL_ACTIVE_TEXTURE 0x8016
#endif
#ifndef GL_CURRENT_PROGRAM
#define GL_CURRENT_PROGRAM 0x8B8D
#endif
#ifndef GL_VERTEX_ARRAY_BINDING
#define GL_VERTEX_ARRAY_BINDING 0x85BB
#endif
#ifndef GL_FRAMEBUFFER_BINDING
#define GL_FRAMEBUFFER_BINDING 0x8CA6
#endif
#ifndef GL_FRAMEBUFFER
#define GL_FRAMEBUFFER 0x8D40
#endif
#ifndef GL_BLEND_SRC_RGB
#define GL_BLEND_SRC_RGB 0x80C9
#endif
#ifndef GL_BLEND_DST_RGB
#define GL_BLEND_DST_RGB 0x80CA
#endif
#ifndef GL_BLEND_SRC_ALPHA
#define GL_BLEND_SRC_ALPHA 0x80CB
#endif
#ifndef GL_BLEND_DST_ALPHA
#define GL_BLEND_DST_ALPHA 0x80CC
#endif

typedef void (APIENTRY* PFNGLACTIVETEXTUREPROC)(GLenum texture);
typedef void (APIENTRY* PFNGLUSEPROGRAMPROC)(GLuint program);
typedef void (APIENTRY* PFNGLBINDVERTEXARRAYPROC)(GLuint array);
typedef void (APIENTRY* PFNGLBINDFRAMEBUFFERPROC)(GLenum target, GLuint framebuffer);
typedef void (APIENTRY* PFNGLBLENDFUNCSEPARATEPROC)(GLenum srcRGB, GLenum dstRGB, GLenum srcAlpha, GLenum dstAlpha);

static PFNGLACTIVETEXTUREPROC glActiveTexture = nullptr;
static PFNGLUSEPROGRAMPROC glUseProgram = nullptr;
static PFNGLBINDVERTEXARRAYPROC glBindVertexArray = nullptr;
static PFNGLBINDFRAMEBUFFERPROC glBindFramebuffer = nullptr;
static PFNGLBLENDFUNCSEPARATEPROC glBlendFuncSeparate = nullptr;

static bool loadGLFunctions() {
    static bool loaded = false;
    if (loaded) return true;

    glActiveTexture = (PFNGLACTIVETEXTUREPROC)wglGetProcAddress("glActiveTexture");
    glUseProgram = (PFNGLUSEPROGRAMPROC)wglGetProcAddress("glUseProgram");
    glBindVertexArray = (PFNGLBINDVERTEXARRAYPROC)wglGetProcAddress("glBindVertexArray");
    glBindFramebuffer = (PFNGLBINDFRAMEBUFFERPROC)wglGetProcAddress("glBindFramebuffer");
    glBlendFuncSeparate = (PFNGLBLENDFUNCSEPARATEPROC)wglGetProcAddress("glBlendFuncSeparate");

    loaded = (glActiveTexture && glUseProgram && glBindVertexArray &&
              glBindFramebuffer && glBlendFuncSeparate);
    return loaded;
}

void GLStateManager::save() {
    if (!loadGLFunctions()) return;

    glGetIntegerv(GL_ACTIVE_TEXTURE, &savedState.activeTexture);
    glGetIntegerv(GL_CURRENT_PROGRAM, &savedState.currentProgram);
    glGetIntegerv(GL_TEXTURE_BINDING_2D, &savedState.textureBinding2D);
    glGetIntegerv(GL_VERTEX_ARRAY_BINDING, &savedState.vertexArrayBinding);
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &savedState.framebufferBinding);

    savedState.blendEnabled = glIsEnabled(GL_BLEND);
    glGetIntegerv(GL_BLEND_SRC_RGB, &savedState.blendSrcRGB);
    glGetIntegerv(GL_BLEND_DST_RGB, &savedState.blendDstRGB);
    glGetIntegerv(GL_BLEND_SRC_ALPHA, &savedState.blendSrcAlpha);
    glGetIntegerv(GL_BLEND_DST_ALPHA, &savedState.blendDstAlpha);

    savedState.depthTestEnabled = glIsEnabled(GL_DEPTH_TEST);
    savedState.cullFaceEnabled = glIsEnabled(GL_CULL_FACE);
    savedState.scissorTestEnabled = glIsEnabled(GL_SCISSOR_TEST);

    glGetIntegerv(GL_VIEWPORT, savedState.viewport);
}

void GLStateManager::restore() {
    if (!loadGLFunctions()) return;

    glActiveTexture(savedState.activeTexture);
    glUseProgram(savedState.currentProgram);
    glBindTexture(GL_TEXTURE_2D, savedState.textureBinding2D);
    glBindVertexArray(savedState.vertexArrayBinding);
    glBindFramebuffer(GL_FRAMEBUFFER, savedState.framebufferBinding);

    if (savedState.blendEnabled) {
        glEnable(GL_BLEND);
    } else {
        glDisable(GL_BLEND);
    }
    glBlendFuncSeparate(savedState.blendSrcRGB, savedState.blendDstRGB,
                        savedState.blendSrcAlpha, savedState.blendDstAlpha);

    if (savedState.depthTestEnabled) {
        glEnable(GL_DEPTH_TEST);
    } else {
        glDisable(GL_DEPTH_TEST);
    }

    if (savedState.cullFaceEnabled) {
        glEnable(GL_CULL_FACE);
    } else {
        glDisable(GL_CULL_FACE);
    }

    if (savedState.scissorTestEnabled) {
        glEnable(GL_SCISSOR_TEST);
    } else {
        glDisable(GL_SCISSOR_TEST);
    }

    glViewport(savedState.viewport[0], savedState.viewport[1],
               savedState.viewport[2], savedState.viewport[3]);
}
