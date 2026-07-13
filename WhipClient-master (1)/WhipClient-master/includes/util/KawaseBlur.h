#pragma once

#include <vector>
#include <string>

struct ImDrawList;
struct ImDrawCmd;

class KawaseBlur {
public:
    static KawaseBlur* getInstance();

    void init();

    struct BlurParams {
        float strength;
        float cornerRadius;
        struct { float x, y, z, w; } rect;
        struct { float r, g, b, a; } tint;
    };

    void prepare(float screenWidth, float screenHeight, float strength);

    void renderMasked(const BlurParams& params);

    void renderBlur(float screenWidth, float screenHeight, const BlurParams& params, const ImDrawCmd* cmd = nullptr);

    static void renderDrawListBlur(const ImDrawList* parent_list, const ImDrawCmd* cmd);

private:
    KawaseBlur() = default;
    ~KawaseBlur() = default;

    void createShaders();
    void createBuffers(int width, int height);
    void deleteBuffers();

    unsigned int shaderProgram = 0;
    unsigned int vao = 0;
    unsigned int vbo = 0;

    unsigned int fbos[2] = {0, 0};
    unsigned int textures[2] = {0, 0};

    bool initialized = false;
    int currentWidth = 0;
    int currentHeight = 0;
    int lastFrameCount = -1;
};
