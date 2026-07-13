#include "../includes/util/KawaseBlur.h"
#include <imgui.h>

#include <windows.h>
#include <GL/gl.h>
#include <iostream>
#include <vector>

#ifndef GL_FRAGMENT_SHADER
#define GL_FRAGMENT_SHADER 0x8B30
#endif
#ifndef GL_VERTEX_SHADER
#define GL_VERTEX_SHADER 0x8B31
#endif
#ifndef GL_ARRAY_BUFFER
#define GL_ARRAY_BUFFER 0x8892
#endif
#ifndef GL_STATIC_DRAW
#define GL_STATIC_DRAW 0x88E4
#endif
#ifndef GL_STREAM_DRAW
#define GL_STREAM_DRAW 0x88E0
#endif
#ifndef GL_DYNAMIC_DRAW
#define GL_DYNAMIC_DRAW 0x88E8
#endif
#ifndef GL_TEXTURE0
#define GL_TEXTURE0 0x84C0
#endif
#ifndef GL_LINK_STATUS
#define GL_LINK_STATUS 0x8B82
#endif
#ifndef GL_COMPILE_STATUS
#define GL_COMPILE_STATUS 0x8B81
#endif
#ifndef GL_CURRENT_PROGRAM
#define GL_CURRENT_PROGRAM 0x8B8D
#endif
#ifndef GL_VERTEX_ARRAY_BINDING
#define GL_VERTEX_ARRAY_BINDING 0x85B5
#endif
#ifndef GL_ARRAY_BUFFER_BINDING
#define GL_ARRAY_BUFFER_BINDING 0x8894
#endif
#ifndef GL_ACTIVE_TEXTURE
#define GL_ACTIVE_TEXTURE 0x84E0
#endif
#ifndef GL_BLEND
#define GL_BLEND 0x0BE2
#endif
#ifndef GL_DEPTH_TEST
#define GL_DEPTH_TEST 0x0B71
#endif
#ifndef GL_SCISSOR_TEST
#define GL_SCISSOR_TEST 0x0C11
#endif
#ifndef GL_CLAMP_TO_EDGE
#define GL_CLAMP_TO_EDGE 0x812F
#endif
#ifndef GL_FRAMEBUFFER
#define GL_FRAMEBUFFER 0x8D40
#endif
#ifndef GL_COLOR_ATTACHMENT0
#define GL_COLOR_ATTACHMENT0 0x8CE0
#endif
#ifndef GL_FRAMEBUFFER_COMPLETE
#define GL_FRAMEBUFFER_COMPLETE 0x8CD5
#endif

typedef char GLchar;
typedef ptrdiff_t GLsizeiptr;
typedef ptrdiff_t GLintptr;

typedef void (APIENTRY *PFNGLGENVERTEXARRAYSPROC) (GLsizei n, GLuint *arrays);
typedef void (APIENTRY *PFNGLBINDVERTEXARRAYPROC) (GLuint array);
typedef void (APIENTRY *PFNGLGENBUFFERSPROC) (GLsizei n, GLuint *buffers);
typedef void (APIENTRY *PFNGLBINDBUFFERPROC) (GLenum target, GLuint buffer);
typedef void (APIENTRY *PFNGLBUFFERDATAPROC) (GLenum target, GLsizeiptr size, const void *data, GLenum usage);
typedef void (APIENTRY *PFNGLENABLEVERTEXATTRIBARRAYPROC) (GLuint index);
typedef void (APIENTRY *PFNGLVERTEXATTRIBPOINTERPROC) (GLuint index, GLint size, GLenum type, GLboolean normalized, GLsizei stride, const void *pointer);
typedef GLuint (APIENTRY *PFNGLCREATESHADERPROC) (GLenum type);
typedef void (APIENTRY *PFNGLSHADERSOURCEPROC) (GLuint shader, GLsizei count, const GLchar *const*string, const GLint *length);
typedef void (APIENTRY *PFNGLCOMPILESHADERPROC) (GLuint shader);
typedef GLuint (APIENTRY *PFNGLCREATEPROGRAMPROC) (void);
typedef void (APIENTRY *PFNGLATTACHSHADERPROC) (GLuint program, GLuint shader);
typedef void (APIENTRY *PFNGLLINKPROGRAMPROC) (GLuint program);
typedef void (APIENTRY *PFNGLDELETESHADERPROC) (GLuint shader);
typedef void (APIENTRY *PFNGLUSEPROGRAMPROC) (GLuint program);
typedef GLint (APIENTRY *PFNGLGETUNIFORMLOCATIONPROC) (GLuint program, const GLchar *name);
typedef void (APIENTRY *PFNGLUNIFORM1FPROC) (GLint location, GLfloat v0);
typedef void (APIENTRY *PFNGLUNIFORM2FPROC) (GLint location, GLfloat v0, GLfloat v1);
typedef void (APIENTRY *PFNGLUNIFORM1IPROC) (GLint location, GLint v0);
typedef void (APIENTRY *PFNGLUNIFORM4FPROC) (GLint location, GLfloat v0, GLfloat v1, GLfloat v2, GLfloat v3);
typedef void (APIENTRY *PFNGLACTIVETEXTUREPROC) (GLenum texture);
typedef void (APIENTRY *PFNGLDISABLEVERTEXATTRIBARRAYPROC) (GLuint index);
typedef void (APIENTRY *PFNGLGENFRAMEBUFFERSPROC) (GLsizei n, GLuint *framebuffers);
typedef void (APIENTRY *PFNGLBINDFRAMEBUFFERPROC) (GLenum target, GLuint framebuffer);
typedef void (APIENTRY *PFNGLFRAMEBUFFERTEXTURE2DPROC) (GLenum target, GLenum attachment, GLenum textarget, GLuint texture, GLint level);
typedef GLenum (APIENTRY *PFNGLCHECKFRAMEBUFFERSTATUSPROC) (GLenum target);
typedef void (APIENTRY *PFNGLDELETEFRAMEBUFFERSPROC) (GLsizei n, const GLuint *framebuffers);

static PFNGLGENVERTEXARRAYSPROC glGenVertexArrays = nullptr;
static PFNGLBINDVERTEXARRAYPROC glBindVertexArray = nullptr;
static PFNGLGENBUFFERSPROC glGenBuffers = nullptr;
static PFNGLBINDBUFFERPROC glBindBuffer = nullptr;
static PFNGLBUFFERDATAPROC glBufferData = nullptr;
static PFNGLENABLEVERTEXATTRIBARRAYPROC glEnableVertexAttribArray = nullptr;
static PFNGLVERTEXATTRIBPOINTERPROC glVertexAttribPointer = nullptr;
static PFNGLCREATESHADERPROC glCreateShader = nullptr;
static PFNGLSHADERSOURCEPROC glShaderSource = nullptr;
static PFNGLCOMPILESHADERPROC glCompileShader = nullptr;
static PFNGLCREATEPROGRAMPROC glCreateProgram = nullptr;
static PFNGLATTACHSHADERPROC glAttachShader = nullptr;
static PFNGLLINKPROGRAMPROC glLinkProgram = nullptr;
static PFNGLDELETESHADERPROC glDeleteShader = nullptr;
static PFNGLUSEPROGRAMPROC glUseProgram = nullptr;
static PFNGLGETUNIFORMLOCATIONPROC glGetUniformLocation = nullptr;
static PFNGLUNIFORM1FPROC glUniform1f = nullptr;
static PFNGLUNIFORM2FPROC glUniform2f = nullptr;
static PFNGLUNIFORM1IPROC glUniform1i = nullptr;
static PFNGLUNIFORM4FPROC glUniform4f = nullptr;
static PFNGLACTIVETEXTUREPROC glActiveTexture = nullptr;
static PFNGLDISABLEVERTEXATTRIBARRAYPROC glDisableVertexAttribArray = nullptr;
static PFNGLGENFRAMEBUFFERSPROC glGenFramebuffers = nullptr;
static PFNGLBINDFRAMEBUFFERPROC glBindFramebuffer = nullptr;
static PFNGLFRAMEBUFFERTEXTURE2DPROC glFramebufferTexture2D = nullptr;
static PFNGLCHECKFRAMEBUFFERSTATUSPROC glCheckFramebufferStatus = nullptr;
static PFNGLDELETEFRAMEBUFFERSPROC glDeleteFramebuffers = nullptr;

static bool glLoadAttempted = false;

static void* getProc(const char* name) {
    void* p = (void*)wglGetProcAddress(name);
    if(p == 0 || (p == (void*)0x1) || (p == (void*)0x2) || (p == (void*)0x3) || (p == (void*)-1)) {
        HMODULE module = LoadLibraryA("opengl32.dll");
        if (module)
            p = (void*)GetProcAddress(module, name);
    }
    return p;
}

static bool loadGL() {
    if (glLoadAttempted) return (glGenVertexArrays != nullptr);
    glLoadAttempted = true;

    glGenVertexArrays = (PFNGLGENVERTEXARRAYSPROC)getProc("glGenVertexArrays");
    glBindVertexArray = (PFNGLBINDVERTEXARRAYPROC)getProc("glBindVertexArray");
    glGenBuffers = (PFNGLGENBUFFERSPROC)getProc("glGenBuffers");
    glBindBuffer = (PFNGLBINDBUFFERPROC)getProc("glBindBuffer");
    glBufferData = (PFNGLBUFFERDATAPROC)getProc("glBufferData");
    glEnableVertexAttribArray = (PFNGLENABLEVERTEXATTRIBARRAYPROC)getProc("glEnableVertexAttribArray");
    glVertexAttribPointer = (PFNGLVERTEXATTRIBPOINTERPROC)getProc("glVertexAttribPointer");
    glCreateShader = (PFNGLCREATESHADERPROC)getProc("glCreateShader");
    glShaderSource = (PFNGLSHADERSOURCEPROC)getProc("glShaderSource");
    glCompileShader = (PFNGLCOMPILESHADERPROC)getProc("glCompileShader");
    glCreateProgram = (PFNGLCREATEPROGRAMPROC)getProc("glCreateProgram");
    glAttachShader = (PFNGLATTACHSHADERPROC)getProc("glAttachShader");
    glLinkProgram = (PFNGLLINKPROGRAMPROC)getProc("glLinkProgram");
    glDeleteShader = (PFNGLDELETESHADERPROC)getProc("glDeleteShader");
    glUseProgram = (PFNGLUSEPROGRAMPROC)getProc("glUseProgram");
    glGetUniformLocation = (PFNGLGETUNIFORMLOCATIONPROC)getProc("glGetUniformLocation");
    glUniform1f = (PFNGLUNIFORM1FPROC)getProc("glUniform1f");
    glUniform2f = (PFNGLUNIFORM2FPROC)getProc("glUniform2f");
    glUniform1i = (PFNGLUNIFORM1IPROC)getProc("glUniform1i");
    glUniform4f = (PFNGLUNIFORM4FPROC)getProc("glUniform4f");
    glActiveTexture = (PFNGLACTIVETEXTUREPROC)getProc("glActiveTexture");
    glDisableVertexAttribArray = (PFNGLDISABLEVERTEXATTRIBARRAYPROC)getProc("glDisableVertexAttribArray");
    glGenFramebuffers = (PFNGLGENFRAMEBUFFERSPROC)getProc("glGenFramebuffers");
    glBindFramebuffer = (PFNGLBINDFRAMEBUFFERPROC)getProc("glBindFramebuffer");
    glFramebufferTexture2D = (PFNGLFRAMEBUFFERTEXTURE2DPROC)getProc("glFramebufferTexture2D");
    glCheckFramebufferStatus = (PFNGLCHECKFRAMEBUFFERSTATUSPROC)getProc("glCheckFramebufferStatus");
    glDeleteFramebuffers = (PFNGLDELETEFRAMEBUFFERSPROC)getProc("glDeleteFramebuffers");

    if (!glGenVertexArrays || !glBindVertexArray) {
        return false;
    }
    if (!glCreateProgram || !glCreateShader) {
        return false;
    }
    if (!glGenFramebuffers || !glBindFramebuffer || !glFramebufferTexture2D || !glCheckFramebufferStatus) {
        return false;
    }

    return true;
}

static const char* vertexShaderSource = R"(
#version 120
attribute vec2 aPos;
attribute vec2 aTexCoord;

varying vec2 TexCoord;

void main() {
    gl_Position = vec4(aPos, 0.0, 1.0);
    TexCoord = aTexCoord;
}
)";

static const char* fragmentShaderSource = R"(
#version 120
varying vec2 TexCoord;

uniform sampler2D screenTexture;
uniform vec2 resolution;
uniform float offset;
uniform int passType;   // 0 = downsample,  1 = upsample

uniform vec4 clipRect;
uniform float radius;
uniform int isFinalPass;
uniform vec4 tintColor;
uniform float viewportY;

float roundRectSDF(vec2 p, vec2 b, float r) {
    vec2 q = abs(p) - b + r;
    return min(max(q.x, q.y), 0.0) + length(max(q, 0.0)) - r;
}

// Simple noise for grain to hide banding and add texture
float noise(vec2 co) {
    return fract(sin(dot(co.xy, vec2(12.9898, 78.233))) * 43758.5453);
}

void main() {
    vec2 res = 1.0 / resolution;

    if (isFinalPass == 1) {
        vec2 size   = (clipRect.zw - clipRect.xy) * 0.5;
        vec2 center = clipRect.xy + size;
        vec2 p = gl_FragCoord.xy - vec2(center.x, resolution.y + viewportY - center.y);

        float d     = roundRectSDF(p, size, radius);
        float alpha = clamp(-d, 0.0, 1.0);
        if (alpha <= 0.0) discard;

        // Sample blurred texture
        vec3 blurred = texture2D(screenTexture, gl_FragCoord.xy / resolution).rgb;

        // --- Premium Glassmorphism Enhancements ---

        // 1. Subtle Luma Grain (prevents banding, adds premium texture)
        float n = (noise(gl_FragCoord.xy * 0.01) - 0.5) * 0.012;
        blurred += n;

        // 2. Brightness/Vibrancy Boost (Glass effect)
        blurred = mix(blurred, blurred * 1.08 + 0.015, 0.6);

        // 3. Inner Glow / Edge Highlight (Depth)
        float highlight = smoothstep(-2.5, 0.0, d) * 0.06;
        blurred += vec3(highlight);

        // 4. Subtle Inner Shadow (helps text readability)
        float innerShadow = smoothstep(-12.0, -2.0, d);
        blurred = mix(blurred * 0.96, blurred, innerShadow);

        // Final Tinting
        vec3 tinted  = mix(blurred, tintColor.rgb, tintColor.a);

        gl_FragColor = vec4(tinted, alpha * tintColor.a); // Use tint alpha for whole glass area
        return;
    }

    if (passType == 0) {
        // Dual Kawase Downsample
        float h = offset + 0.5;
        vec3 color  = texture2D(screenTexture, TexCoord).rgb * 4.0;
        color += texture2D(screenTexture, TexCoord + vec2(-h,  h) * res).rgb;
        color += texture2D(screenTexture, TexCoord + vec2( h,  h) * res).rgb;
        color += texture2D(screenTexture, TexCoord + vec2(-h, -h) * res).rgb;
        color += texture2D(screenTexture, TexCoord + vec2( h, -h) * res).rgb;
        gl_FragColor = vec4(color / 8.0, 1.0);
    } else {
        // Dual Kawase Upsample
        float o = offset;
        vec3 color  = texture2D(screenTexture, TexCoord + vec2(-2.0*o,      0.0) * res).rgb;
        color      += texture2D(screenTexture, TexCoord + vec2(    -o,       o)  * res).rgb * 2.0;
        color      += texture2D(screenTexture, TexCoord + vec2(   0.0,  2.0*o)   * res).rgb;
        color      += texture2D(screenTexture, TexCoord + vec2(     o,       o)  * res).rgb * 2.0;
        color      += texture2D(screenTexture, TexCoord + vec2( 2.0*o,     0.0)  * res).rgb;
        color      += texture2D(screenTexture, TexCoord + vec2(     o,      -o)  * res).rgb * 2.0;
        color      += texture2D(screenTexture, TexCoord + vec2(   0.0, -2.0*o)   * res).rgb;
        color      += texture2D(screenTexture, TexCoord + vec2(    -o,      -o)  * res).rgb * 2.0;
        gl_FragColor = vec4(color / 12.0, 1.0);
    }
}
)";

KawaseBlur* KawaseBlur::getInstance() {
    static KawaseBlur instance;
    return &instance;
}

void KawaseBlur::init() {
    if (initialized) return;

    if (!loadGL()) {return;
    }

    createShaders();
    if (!shaderProgram) return;

    glGenBuffers(1, &vbo);

    initialized = true;
}

void KawaseBlur::createShaders() {
    unsigned int vertexShader = glCreateShader(GL_VERTEX_SHADER);
    glShaderSource(vertexShader, 1, &vertexShaderSource, NULL);
    glCompileShader(vertexShader);

    unsigned int fragmentShader = glCreateShader(GL_FRAGMENT_SHADER);
    glShaderSource(fragmentShader, 1, &fragmentShaderSource, NULL);
    glCompileShader(fragmentShader);

    shaderProgram = glCreateProgram();
    glAttachShader(shaderProgram, vertexShader);
    glAttachShader(shaderProgram, fragmentShader);
    glLinkProgram(shaderProgram);

    GLint success;

    glDeleteShader(vertexShader);
    glDeleteShader(fragmentShader);
}

void KawaseBlur::createBuffers(int width, int height) {
    if (currentWidth == width && currentHeight == height && initialized && textures[0] != 0) return;
    deleteBuffers();

    currentWidth = width;
    currentHeight = height;

    glGenTextures(2, textures);
    glGenFramebuffers(2, fbos);

    for (int i = 0; i < 2; i++) {
        glBindTexture(GL_TEXTURE_2D, textures[i]);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, width, height, 0, GL_RGB, GL_UNSIGNED_BYTE, NULL);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

        glBindFramebuffer(GL_FRAMEBUFFER, fbos[i]);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, textures[i], 0);
    }
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glBindTexture(GL_TEXTURE_2D, 0);
}

void KawaseBlur::deleteBuffers() {
    if (textures[0]) {
        glDeleteTextures(2, textures);
        textures[0] = textures[1] = 0;
    }
    if (fbos[0]) {
        glDeleteFramebuffers(2, fbos);
        fbos[0] = fbos[1] = 0;
    }
}

void KawaseBlur::prepare(float screenWidth, float screenHeight, float strength) {
    if (screenWidth <= 0 || screenHeight <= 0) return;
    if (!initialized) init();
    if (!initialized || !shaderProgram) return;

    const int passes = 6;
    createBuffers((int)screenWidth, (int)screenHeight);

    if (ImGui::GetCurrentContext()) {
        int frameCount = ImGui::GetFrameCount();
        if (frameCount == lastFrameCount) {
            return;
        }
        lastFrameCount = frameCount;
    }

    if (glActiveTexture) glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, textures[0]);

    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glCopyTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 0, 0, currentWidth, currentHeight);

    glUseProgram(shaderProgram);
    if (glBindVertexArray && vao) glBindVertexArray(vao);
    else glBindBuffer(GL_ARRAY_BUFFER, vbo);

    if (glUniform2f)
        glUniform2f(glGetUniformLocation(shaderProgram, "resolution"), (float)currentWidth, (float)currentHeight);

    if (glUniform1i) {
        glUniform1i(glGetUniformLocation(shaderProgram, "screenTexture"), 0);
        glUniform1i(glGetUniformLocation(shaderProgram, "isFinalPass"), 0);
    }

    GLint last_viewport[4]; glGetIntegerv(GL_VIEWPORT, last_viewport);
    GLint last_fbo = 0; glGetIntegerv(0x8CA6, &last_fbo);

    try {
        glViewport(0, 0, currentWidth, currentHeight);

        float fsVertices[] = {
            -1.0f,  1.0f,  0.0f, 1.0f,
            -1.0f, -1.0f,  0.0f, 0.0f,
             1.0f, -1.0f,  1.0f, 0.0f,
            -1.0f,  1.0f,  0.0f, 1.0f,
             1.0f, -1.0f,  1.0f, 0.0f,
             1.0f,  1.0f,  1.0f, 1.0f
        };

        if (glBindVertexArray) glBindVertexArray(0);
        glBindBuffer(GL_ARRAY_BUFFER, vbo);
        glBufferData(GL_ARRAY_BUFFER, sizeof(fsVertices), fsVertices, GL_DYNAMIC_DRAW);

        glEnableVertexAttribArray(0);
        glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(float), (void*)0);
        glEnableVertexAttribArray(1);
        glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(float), (void*)(2 * sizeof(float)));

        const GLint locPassType = glGetUniformLocation(shaderProgram, "passType");
        const GLint locOffset   = glGetUniformLocation(shaderProgram, "offset");

        for (int i = 0; i < passes; i++) {
            const int  passType   = i % 2;
            const float passOffset = strength * (float)(i / 2 + 1);

            glBindFramebuffer(GL_FRAMEBUFFER, fbos[1]);
            glBindTexture(GL_TEXTURE_2D, textures[0]);

            if (glUniform1i) glUniform1i(locPassType, passType);
            if (glUniform1f) glUniform1f(locOffset,   passOffset);

            glDrawArrays(GL_TRIANGLES, 0, 6);

            unsigned int tempTex = textures[0];
            textures[0] = textures[1];
            textures[1] = tempTex;

            unsigned int tempFbo = fbos[0];
            fbos[0] = fbos[1];
            fbos[1] = tempFbo;
        }

        glDisableVertexAttribArray(0);
        glDisableVertexAttribArray(1);
        glBindBuffer(GL_ARRAY_BUFFER, 0);
    }
    catch (...) {

        glDisableVertexAttribArray(0);
        glDisableVertexAttribArray(1);
        glBindBuffer(GL_ARRAY_BUFFER, 0);
    }

    glViewport(last_viewport[0], last_viewport[1], last_viewport[2], last_viewport[3]);
    glBindFramebuffer(GL_FRAMEBUFFER, last_fbo);
    glUseProgram(0);
}

void KawaseBlur::renderMasked(const BlurParams& params) {
    if (!initialized || !shaderProgram || !textures[0]) return;

    try {

        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

        glUseProgram(shaderProgram);
        if (glActiveTexture) glActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_2D, textures[0]);

        if (glUniform2f)
            glUniform2f(glGetUniformLocation(shaderProgram, "resolution"), (float)currentWidth, (float)currentHeight);

        if (glUniform1i) {
            glUniform1i(glGetUniformLocation(shaderProgram, "isFinalPass"), 1);
            glUniform1i(glGetUniformLocation(shaderProgram, "screenTexture"), 0);
            glUniform1i(glGetUniformLocation(shaderProgram, "passType"), 0);
        }

        if (glUniform4f)
            glUniform4f(glGetUniformLocation(shaderProgram, "clipRect"), params.rect.x, params.rect.y, params.rect.z, params.rect.w);

        if (glUniform1f) {
            glUniform1f(glGetUniformLocation(shaderProgram, "radius"), params.cornerRadius);
            glUniform1f(glGetUniformLocation(shaderProgram, "offset"), 0.0f);

            GLint vp[4]; glGetIntegerv(GL_VIEWPORT, vp);
            glUniform1f(glGetUniformLocation(shaderProgram, "viewportY"), (float)vp[1]);
        }

        if (glUniform4f)
            glUniform4f(glGetUniformLocation(shaderProgram, "tintColor"),
                params.tint.r, params.tint.g, params.tint.b, params.tint.a);

        float x1 = (params.rect.x / currentWidth) * 2.0f - 1.0f;
        float y1 = (params.rect.y / currentHeight) * -2.0f + 1.0f;
        float x2 = (params.rect.z / currentWidth) * 2.0f - 1.0f;
        float y2 = (params.rect.w / currentHeight) * -2.0f + 1.0f;

        float quadVertices[] = {
            x1, y1, 0.0f, 1.0f,
            x1, y2, 0.0f, 0.0f,
            x2, y2, 1.0f, 0.0f,
            x1, y1, 0.0f, 1.0f,
            x2, y2, 1.0f, 0.0f,
            x2, y1, 1.0f, 1.0f
        };

        if (glBindVertexArray) glBindVertexArray(0);

        glBindBuffer(GL_ARRAY_BUFFER, vbo);
        glBufferData(GL_ARRAY_BUFFER, sizeof(quadVertices), quadVertices, GL_DYNAMIC_DRAW);

        glEnableVertexAttribArray(0);
        glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(float), (void*)0);
        glEnableVertexAttribArray(1);
        glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(float), (void*)(2 * sizeof(float)));

        glDrawArrays(GL_TRIANGLES, 0, 6);
    }
    catch (...) {

    }

    glDisableVertexAttribArray(0);
    glDisableVertexAttribArray(1);
    glBindBuffer(GL_ARRAY_BUFFER, 0);
    glUseProgram(0);
}

void KawaseBlur::renderBlur(float screenWidth, float screenHeight, const BlurParams& params, const ImDrawCmd* cmd) {

    GLint last_program; glGetIntegerv(GL_CURRENT_PROGRAM, &last_program);
    GLint last_texture; glGetIntegerv(GL_TEXTURE_BINDING_2D, &last_texture);
    GLint last_active_texture; glGetIntegerv(GL_ACTIVE_TEXTURE, &last_active_texture);
    GLint last_array_buffer; glGetIntegerv(GL_ARRAY_BUFFER_BINDING, &last_array_buffer);
    GLint last_vertex_array = 0; if (glBindVertexArray && vao) glGetIntegerv(0x8E25, &last_vertex_array);
    GLint last_fbo; glGetIntegerv(0x8CA6, &last_fbo);
    GLboolean last_enable_blend = glIsEnabled(GL_BLEND);
    GLboolean last_enable_depth = glIsEnabled(GL_DEPTH_TEST);
    GLboolean last_enable_scissor = glIsEnabled(GL_SCISSOR_TEST);

    try {
        glDisable(GL_BLEND);
        glDisable(GL_DEPTH_TEST);
        glDisable(GL_SCISSOR_TEST);

        prepare(screenWidth, screenHeight, params.strength);

        glBindFramebuffer(GL_FRAMEBUFFER, last_fbo);

        {
            GLint vp[4]; glGetIntegerv(GL_VIEWPORT, vp);
            glEnable(GL_SCISSOR_TEST);
            glScissor(
                vp[0] + (int)params.rect.x,
                vp[1] + vp[3] - (int)params.rect.w,
                (int)(params.rect.z - params.rect.x),
                (int)(params.rect.w - params.rect.y)
            );
        }

        renderMasked(params);
    }
    catch (...) {

    }

    glUseProgram(last_program);
    if (glActiveTexture) glActiveTexture(last_active_texture);
    glBindTexture(GL_TEXTURE_2D, last_texture);
    if (glBindVertexArray && vao) glBindVertexArray(last_vertex_array);
    glBindBuffer(GL_ARRAY_BUFFER, last_array_buffer);
    glBindFramebuffer(GL_FRAMEBUFFER, last_fbo);

    if (last_enable_scissor) glEnable(GL_SCISSOR_TEST); else glDisable(GL_SCISSOR_TEST);
    if (last_enable_blend) glEnable(GL_BLEND); else glDisable(GL_BLEND);
    if (last_enable_depth) glEnable(GL_DEPTH_TEST); else glDisable(GL_DEPTH_TEST);

    if (glDisableVertexAttribArray) {
        glDisableVertexAttribArray(0);
        glDisableVertexAttribArray(1);
    }
}

void KawaseBlur::renderDrawListBlur(const ImDrawList* parent_list, const ImDrawCmd* cmd) {
    if (!cmd->UserCallbackData) return;

    GLint viewport[4];
    glGetIntegerv(GL_VIEWPORT, viewport);

    const BlurParams* params = (const BlurParams*)cmd->UserCallbackData;
    KawaseBlur::getInstance()->renderBlur((float)viewport[2], (float)viewport[3], *params, cmd);
}
