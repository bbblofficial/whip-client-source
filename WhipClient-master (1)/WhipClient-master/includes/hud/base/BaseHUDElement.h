#pragma once

#define IMGUI_DEFINE_MATH_OPERATORS
#include "../IHUDElement.h"
#include <imgui.h>

class BaseHUDElement : public IHUDElement {
protected:
    bool enabled;
    float x, y;
    float width, height;

    ImColor GetRainbowColor(int offset, float saturation, float speed = 1.0f);
    ImColor GetWaveColor(ImColor colorA, ImColor colorB, double delay, bool inverse, float position);
    ImColor GetGradientColor(ImColor colorA, ImColor colorB, float progress);
    ImColor GetAstolfoColor(int index, float speed, float saturation, ImColor baseColor);
    ImColor GetFadeColor(ImColor colorA, ImColor colorB, int index, float speed);

public:
    explicit BaseHUDElement(float posX = 0.0f, float posY = 0.0f);

    ~BaseHUDElement() override = default;

    bool isEnabled() const { return enabled; }
    float getX() const { return x; }
    float getY() const { return y; }
    float getWidth() const { return width; }
    float getHeight() const { return height; }

    void setEnabled(const bool state) { enabled = state; }
    void setPosition(const float posX, const float posY) { x = posX; y = posY; }
    void setSize(const float w, const float h) { width = w; height = h; }

    void render() override;

protected:
    virtual void onRender() = 0;
};
