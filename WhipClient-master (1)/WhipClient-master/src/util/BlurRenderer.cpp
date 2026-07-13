#include "util/BlurRenderer.h"
#include "util/BlurShaders.h"
#include <cstring>

#ifndef GLchar
typedef char GLchar;
#endif

typedef GLuint (APIENTRY* PFNGLCREATESHADERPROC)(GLenum type);
typedef void (APIENTRY* PFNGLSHADERSOURCEPROC)(GLuint shader, GLsizei count, const GLchar** string, const GLint* length);
typedef void (APIENTRY* PFNGLCOMPILESHADERPROC)(GLuint shader);
typedef void (APIENTRY* PFNGLGETSHADERIVPROC)(GLuint shader, GLenum pname, GLint* params);
typedef void (APIENTRY* PFNGLGETSHADERINFOLOGPROC)(GLuint shader, GLsizei bufSize, GLsizei* length, GLchar* infoLog);
typedef GLuint (APIENTRY* PFNGLCREATEPROGRAMPROC)();
typedef void (APIENTRY* PFNGLATTACHSHADERPROC)(GLuint program, GLuint shader);
typedef void (APIENTRY* PFNGLLINKPROGRAMPROC)(GLuint program);
typedef void (APIENTRY* PFNGLGETPROGRAMIVPROC)(GLuint program, GLenum pname, GLint* params);
typedef void (APIENTRY* PFNGLGETPROGRAMINFOLOGPROC)(GLuint program, GLsizei bufSize, GLsizei* length, GLchar* infoLog);
typedef void (APIENTRY* PFNGLUSEPROGRAMPROC)(GLuint program);
typedef void (APIENTRY* PFNGLDELETESHADERPROC)(GLuint shader);
typedef void (APIENTRY* PFNGLDELETEPROGRAMPROC)(GLuint program);
typedef GLint (APIENTRY* PFNGLGETUNIFORMLOCATIONPROC)(GLuint program, const GLchar* name);
typedef void (APIENTRY* PFNGLUNIFORM1IPROC)(GLint location, GLint v0);
typedef void (APIENTRY* PFNGLUNIFORM1FPROC)(GLint location, GLfloat v0);
typedef void (APIENTRY* PFNGLUNIFORM2FPROC)(GLint location, GLfloat v0, GLfloat v1);
typedef void (APIENTRY* PFNGLUNIFORMMATRIX4FVPROC)(GLint location, GLsizei count, GLboolean transpose, const GLfloat* value);
typedef void (APIENTRY* PFNGLGENVERTEXARRAYSPROC)(GLsizei n, GLuint* arrays);
typedef void (APIENTRY* PFNGLBINDVERTEXARRAYPROC)(GLuint array);
typedef void (APIENTRY* PFNGLGENBUFFERSPROC)(GLsizei n, GLuint* buffers);
typedef void (APIENTRY* PFNGLBINDBUFFERPROC)(GLenum target, GLuint buffer);
typedef void (APIENTRY* PFNGLBUFFERDATAPROC)(GLenum target, ptrdiff_t size, const void* data, GLenum usage);
typedef void (APIENTRY* PFNGLENABLEVERTEXATTRIBARRAYPROC)(GLuint index);
typedef void (APIENTRY* PFNGLVERTEXATTRIBPOINTERPROC)(GLuint index, GLint size, GLenum type, GLboolean normalized, GLsizei stride, const void* pointer);
typedef void (APIENTRY* PFNGLDELETEVERTEXARRAYSPROC)(GLsizei n, const GLuint* arrays);
typedef void (APIENTRY* PFNGLDELETEBUFFERSPROC)(GLsizei n, const GLuint* buffers);
typedef void (APIENTRY* PFNGLBINDFRAMEBUFFERPROC)(GLenum target, GLuint framebuffer);
typedef void (APIENTRY* PFNGLACTIVETEXTUREPROC)(GLenum texture);

static PFNGLCREATESHADERPROC glCreateShader = nullptr;
static PFNGLSHADERSOURCEPROC glShaderSource = nullptr;
static PFNGLCOMPILESHADERPROC glCompileShader = nullptr;
static PFNGLGETSHADERIVPROC glGetShaderiv = nullptr;
static PFNGLGETSHADERINFOLOGPROC glGetShaderInfoLog = nullptr;
static PFNGLCREATEPROGRAMPROC glCreateProgram = nullptr;
static PFNGLATTACHSHADERPROC glAttachShader = nullptr;
static PFNGLLINKPROGRAMPROC glLinkProgram = nullptr;
static PFNGLGETPROGRAMIVPROC glGetProgramiv = nullptr;
static PFNGLGETPROGRAMINFOLOGPROC glGetProgramInfoLog = nullptr;
static PFNGLUSEPROGRAMPROC glUseProgram = nullptr;
static PFNGLDELETESHADERPROC glDeleteShader = nullptr;
static PFNGLDELETEPROGRAMPROC glDeleteProgram = nullptr;
static PFNGLGETUNIFORMLOCATIONPROC glGetUniformLocation = nullptr;
static PFNGLUNIFORM1IPROC glUniform1i = nullptr;
static PFNGLUNIFORM1FPROC glUniform1f = nullptr;
static PFNGLUNIFORM2FPROC glUniform2f = nullptr;
static PFNGLUNIFORMMATRIX4FVPROC glUniformMatrix4fv = nullptr;
static PFNGLGENVERTEXARRAYSPROC glGenVertexArrays = nullptr;
static PFNGLBINDVERTEXARRAYPROC glBindVertexArray = nullptr;
static PFNGLGENBUFFERSPROC glGenBuffers = nullptr;
static PFNGLBINDBUFFERPROC glBindBuffer = nullptr;
static PFNGLBUFFERDATAPROC glBufferData = nullptr;
static PFNGLENABLEVERTEXATTRIBARRAYPROC glEnableVertexAttribArray = nullptr;
static PFNGLVERTEXATTRIBPOINTERPROC glVertexAttribPointer = nullptr;
static PFNGLDELETEVERTEXARRAYSPROC glDeleteVertexArrays = nullptr;
static PFNGLDELETEBUFFERSPROC glDeleteBuffers = nullptr;
static PFNGLBINDFRAMEBUFFERPROC glBindFramebuffer = nullptr;
static PFNGLACTIVETEXTUREPROC glActiveTexture = nullptr;

static bool loadGLFunctions() {
    static bool loaded = false;
    if (loaded) return true;

    glCreateShader = (PFNGLCREATESHADERPROC)wglGetProcAddress("glCreateShader");
    glShaderSource = (PFNGLSHADERSOURCEPROC)wglGetProcAddress("glShaderSource");
    glCompileShader = (PFNGLCOMPILESHADERPROC)wglGetProcAddress("glCompileShader");
    glGetShaderiv = (PFNGLGETSHADERIVPROC)wglGetProcAddress("glGetShaderiv");
    glGetShaderInfoLog = (PFNGLGETSHADERINFOLOGPROC)wglGetProcAddress("glGetShaderInfoLog");
    glCreateProgram = (PFNGLCREATEPROGRAMPROC)wglGetProcAddress("glCreateProgram");
    glAttachShader = (PFNGLATTACHSHADERPROC)wglGetProcAddress("glAttachShader");
    glLinkProgram = (PFNGLLINKPROGRAMPROC)wglGetProcAddress("glLinkProgram");
    glGetProgramiv = (PFNGLGETPROGRAMIVPROC)wglGetProcAddress("glGetProgramiv");
    glGetProgramInfoLog = (PFNGLGETPROGRAMINFOLOGPROC)wglGetProcAddress("glGetProgramInfoLog");
    glUseProgram = (PFNGLUSEPROGRAMPROC)wglGetProcAddress("glUseProgram");
    glDeleteShader = (PFNGLDELETESHADERPROC)wglGetProcAddress("glDeleteShader");
    glDeleteProgram = (PFNGLDELETEPROGRAMPROC)wglGetProcAddress("glDeleteProgram");
    glGetUniformLocation = (PFNGLGETUNIFORMLOCATIONPROC)wglGetProcAddress("glGetUniformLocation");
    glUniform1i = (PFNGLUNIFORM1IPROC)wglGetProcAddress("glUniform1i");
    glUniform1f = (PFNGLUNIFORM1FPROC)wglGetProcAddress("glUniform1f");
    glUniform2f = (PFNGLUNIFORM2FPROC)wglGetProcAddress("glUniform2f");
    glUniformMatrix4fv = (PFNGLUNIFORMMATRIX4FVPROC)wglGetProcAddress("glUniformMatrix4fv");
    glGenVertexArrays = (PFNGLGENVERTEXARRAYSPROC)wglGetProcAddress("glGenVertexArrays");
    glBindVertexArray = (PFNGLBINDVERTEXARRAYPROC)wglGetProcAddress("glBindVertexArray");
    glGenBuffers = (PFNGLGENBUFFERSPROC)wglGetProcAddress("glGenBuffers");
    glBindBuffer = (PFNGLBINDBUFFERPROC)wglGetProcAddress("glBindBuffer");
    glBufferData = (PFNGLBUFFERDATAPROC)wglGetProcAddress("glBufferData");
    glEnableVertexAttribArray = (PFNGLENABLEVERTEXATTRIBARRAYPROC)wglGetProcAddress("glEnableVertexAttribArray");
    glVertexAttribPointer = (PFNGLVERTEXATTRIBPOINTERPROC)wglGetProcAddress("glVertexAttribPointer");
    glDeleteVertexArrays = (PFNGLDELETEVERTEXARRAYSPROC)wglGetProcAddress("glDeleteVertexArrays");
    glDeleteBuffers = (PFNGLDELETEBUFFERSPROC)wglGetProcAddress("glDeleteBuffers");
    glBindFramebuffer = (PFNGLBINDFRAMEBUFFERPROC)wglGetProcAddress("glBindFramebuffer");
    glActiveTexture = (PFNGLACTIVETEXTUREPROC)wglGetProcAddress("glActiveTexture");

    loaded = (glCreateShader && glShaderSource && glCompileShader && glGetShaderiv &&
              glGetShaderInfoLog && glCreateProgram && glAttachShader && glLinkProgram &&
              glGetProgramiv && glGetProgramInfoLog && glUseProgram && glDeleteShader &&
              glDeleteProgram && glGetUniformLocation && glUniform1i && glUniform1f &&
              glUniform2f && glUniformMatrix4fv && glGenVertexArrays && glBindVertexArray &&
              glGenBuffers && glBindBuffer && glBufferData && glEnableVertexAttribArray &&
              glVertexAttribPointer && glDeleteVertexArrays && glDeleteBuffers && glBindFramebuffer &&
              glActiveTexture);

    return loaded;
}

#define GL_VERTEX_SHADER 0x8B31
#define GL_FRAGMENT_SHADER 0x8B30
#define GL_COMPILE_STATUS 0x8B81
#define GL_LINK_STATUS 0x8B82
#define GL_ARRAY_BUFFER 0x8892
#define GL_STATIC_DRAW 0x88E4
#define GL_FRAMEBUFFER 0x8D40
#define GL_TEXTURE0 0x84C0

BlurRenderer::BlurRenderer()
    : blurShaderProgram(0), quadShaderProgram(0),
      quadVAO(0), quadVBO(0),
      blurImageLoc(-1), blurRadiusLoc(-1), blurDirectionLoc(-1),
      quadTextureLoc(-1), quadAlphaLoc(-1), quadProjectionLoc(-1),
      initialized(false), blurRadius(2.0f) {
}

BlurRenderer::~BlurRenderer() {
    shutdown();
}

bool BlurRenderer::compileShader(GLuint* shader, GLenum type, const char* source) {
    if (!glCreateShader || !glShaderSource || !glCompileShader || !glGetShaderiv) {
        return false;
    }

    *shader = glCreateShader(type);
    glShaderSource(*shader, 1, &source, nullptr);
    glCompileShader(*shader);

    GLint success;
    glGetShaderiv(*shader, GL_COMPILE_STATUS, &success);
    if (!success) {
        if (glGetShaderInfoLog) {
            char infoLog[512];
            glGetShaderInfoLog(*shader, 512, nullptr, infoLog);
        }
        return false;
    }
    return true;
}

bool BlurRenderer::linkProgram(GLuint program) {
    if (!glLinkProgram || !glGetProgramiv) {
        return false;
    }

    glLinkProgram(program);

    GLint success;
    glGetProgramiv(program, GL_LINK_STATUS, &success);
    if (!success) {
        if (glGetProgramInfoLog) {
            char infoLog[512];
            glGetProgramInfoLog(program, 512, nullptr, infoLog);
        }
        return false;
    }
    return true;
}

void BlurRenderer::setupQuadGeometry() {
    float quadVertices[] = {

        -1.0f,  1.0f,  0.0f, 1.0f,
        -1.0f, -1.0f,  0.0f, 0.0f,
         1.0f, -1.0f,  1.0f, 0.0f,

        -1.0f,  1.0f,  0.0f, 1.0f,
         1.0f, -1.0f,  1.0f, 0.0f,
         1.0f,  1.0f,  1.0f, 1.0f
    };

    glGenVertexArrays(1, &quadVAO);
    glGenBuffers(1, &quadVBO);

    glBindVertexArray(quadVAO);
    glBindBuffer(GL_ARRAY_BUFFER, quadVBO);
    glBufferData(GL_ARRAY_BUFFER, sizeof(quadVertices), quadVertices, GL_STATIC_DRAW);

    glEnableVertexAttribArray(0);
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(float), (void*)0);

    glEnableVertexAttribArray(1);
    glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(float), (void*)(2 * sizeof(float)));

    glBindVertexArray(0);
}

bool BlurRenderer::initialize() {
    if (!loadGLFunctions()) {
        return false;
    }

    GLuint vertexShader;

    blurShaderProgram = glCreateProgram();

    if (!compileShader(&vertexShader, GL_VERTEX_SHADER, BlurShaders::BLUR_VERTEX_SHADER)) {
        return false;
    }

    GLuint blurFragShader;
    if (!compileShader(&blurFragShader, GL_FRAGMENT_SHADER, BlurShaders::BLUR_FRAGMENT_SHADER)) {
        glDeleteShader(vertexShader);
        return false;
    }

    glAttachShader(blurShaderProgram, vertexShader);
    glAttachShader(blurShaderProgram, blurFragShader);

    if (!linkProgram(blurShaderProgram)) {
        glDeleteShader(vertexShader);
        glDeleteShader(blurFragShader);
        return false;
    }

    glDeleteShader(blurFragShader);

    blurImageLoc = glGetUniformLocation(blurShaderProgram, "image");
    blurRadiusLoc = glGetUniformLocation(blurShaderProgram, "blurRadius");
    blurDirectionLoc = glGetUniformLocation(blurShaderProgram, "blurDirection");

    quadShaderProgram = glCreateProgram();

    GLuint quadVertShader;
    if (!compileShader(&quadVertShader, GL_VERTEX_SHADER, BlurShaders::QUAD_VERTEX_SHADER)) {
        glDeleteShader(vertexShader);
        return false;
    }

    GLuint quadFragShader;
    if (!compileShader(&quadFragShader, GL_FRAGMENT_SHADER, BlurShaders::QUAD_FRAGMENT_SHADER)) {
        glDeleteShader(vertexShader);
        glDeleteShader(quadVertShader);
        return false;
    }

    glAttachShader(quadShaderProgram, quadVertShader);
    glAttachShader(quadShaderProgram, quadFragShader);

    if (!linkProgram(quadShaderProgram)) {
        glDeleteShader(vertexShader);
        glDeleteShader(quadVertShader);
        glDeleteShader(quadFragShader);
        return false;
    }

    glDeleteShader(vertexShader);
    glDeleteShader(quadVertShader);
    glDeleteShader(quadFragShader);

    quadTextureLoc = glGetUniformLocation(quadShaderProgram, "blurredTexture");
    quadAlphaLoc = glGetUniformLocation(quadShaderProgram, "alpha");
    quadProjectionLoc = glGetUniformLocation(quadShaderProgram, "projection");

    setupQuadGeometry();

    initialized = true;
    return true;
}

void BlurRenderer::shutdown() {
    if (!loadGLFunctions()) return;

    if (quadVAO) {
        glDeleteVertexArrays(1, &quadVAO);
        quadVAO = 0;
    }
    if (quadVBO) {
        glDeleteBuffers(1, &quadVBO);
        quadVBO = 0;
    }
    if (blurShaderProgram) {
        glDeleteProgram(blurShaderProgram);
        blurShaderProgram = 0;
    }
    if (quadShaderProgram) {
        glDeleteProgram(quadShaderProgram);
        quadShaderProgram = 0;
    }

    initialized = false;
}

void BlurRenderer::performBlurPass(GLuint inputTexture, GLuint outputFBO,
                                   bool horizontal, int width, int height) {
    if (!initialized) return;

    glBindFramebuffer(GL_FRAMEBUFFER, outputFBO);
    glViewport(0, 0, width, height);

    glUseProgram(blurShaderProgram);
    glBindVertexArray(quadVAO);

    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, inputTexture);
    glUniform1i(blurImageLoc, 0);
    glUniform1f(blurRadiusLoc, blurRadius);
    glUniform2f(blurDirectionLoc, horizontal ? 1.0f : 0.0f, horizontal ? 0.0f : 1.0f);

    glDisable(GL_DEPTH_TEST);
    glDisable(GL_BLEND);
    glDrawArrays(GL_TRIANGLES, 0, 6);

    glBindVertexArray(0);
    glUseProgram(0);
}

void BlurRenderer::renderBlurredQuad(GLuint blurredTexture,
                                    float x, float y, float width, float height,
                                    float screenWidth, float screenHeight,
                                    float alpha) {
    if (!initialized) return;

    float left = 0.0f;
    float right = screenWidth;
    float bottom = screenHeight;
    float top = 0.0f;
    float nearPlane = -1.0f;
    float farPlane = 1.0f;

    float projection[16] = {
        2.0f / (right - left), 0.0f, 0.0f, 0.0f,
        0.0f, 2.0f / (top - bottom), 0.0f, 0.0f,
        0.0f, 0.0f, -2.0f / (farPlane - nearPlane), 0.0f,
        -(right + left) / (right - left), -(top + bottom) / (top - bottom), -(farPlane + nearPlane) / (farPlane - nearPlane), 1.0f
    };

    float x1 = x;
    float y1 = y;
    float x2 = x + width;
    float y2 = y + height;

    float u1 = x1 / screenWidth;
    float u2 = x2 / screenWidth;
    float v1 = 1.0f - y1 / screenHeight;
    float v2 = 1.0f - y2 / screenHeight;

    float quadVerts[] = {
        x1, y1, u1, v1,
        x1, y2, u1, v2,
        x2, y2, u2, v2,

        x1, y1, u1, v1,
        x2, y2, u2, v2,
        x2, y1, u2, v1
    };

    glBindBuffer(GL_ARRAY_BUFFER, quadVBO);
    glBufferData(GL_ARRAY_BUFFER, sizeof(quadVerts), quadVerts, GL_STATIC_DRAW);

    glUseProgram(quadShaderProgram);
    glBindVertexArray(quadVAO);

    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, blurredTexture);
    glUniform1i(quadTextureLoc, 0);
    glUniform1f(quadAlphaLoc, alpha);
    glUniformMatrix4fv(quadProjectionLoc, 1, GL_FALSE, projection);

    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glDisable(GL_DEPTH_TEST);

    glDrawArrays(GL_TRIANGLES, 0, 6);

    glBindVertexArray(0);
    glUseProgram(0);
}
