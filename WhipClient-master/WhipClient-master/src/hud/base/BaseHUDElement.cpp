#include "../../../includes/hud/base/BaseHUDElement.h"
#include "../../../resources/Font/Poppins-Bold.h"
#include "../../../resources/Font/Poppins-SemiBold.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <Windows.h>

#include "imgui_internal.h"
#include "module/impl/visual/ArrayListModule.h"

BaseHUDElement::BaseHUDElement(const float posX, const float posY)
    : enabled(true), x(posX), y(posY), width(0), height(0) {
}

void BaseHUDElement::render() {
    if (enabled) {
        onRender();
    }
}

ImColor BaseHUDElement::GetRainbowColor(int offset, float saturation, float speed) {
    double time = GetTickCount64() * 0.0002 * speed;
    float hue = static_cast<float>(fmod(time + offset * 0.05, 1.0));
    return ImColor::HSV(hue, saturation, 0.8f);
}

ImColor BaseHUDElement::GetWaveColor(ImColor colorA, ImColor colorB, double delay, bool inverse, float position) {
    double time = GetTickCount64() * 0.006;
    float t = 0.0f;

    ImColor finalColorA = inverse ? colorB : colorA;
    ImColor finalColorB = inverse ? colorA : colorB;

    constexpr float waveSpeed = 1.0f;
    constexpr float waveSize = 1.0f;
    t = (std::sin(time * waveSpeed + position * 0.1 + delay * 0.1) * waveSize + waveSize) * 0.5f;

    return ImColor(
        ImLerp(finalColorA.Value.x, finalColorB.Value.x, t),
        ImLerp(finalColorA.Value.y, finalColorB.Value.y, t),
        ImLerp(finalColorA.Value.z, finalColorB.Value.z, t),
        finalColorA.Value.w
    );
}

ImColor BaseHUDElement::GetGradientColor(ImColor colorA, ImColor colorB, float progress) {
    float t = std::clamp(progress, 0.0f, 1.0f);
    return ImColor(
        ImLerp(colorA.Value.x, colorB.Value.x, t),
        ImLerp(colorA.Value.y, colorB.Value.y, t),
        ImLerp(colorA.Value.z, colorB.Value.z, t),
        colorA.Value.w
    );
}

ImColor BaseHUDElement::GetAstolfoColor(int index, float speed, float saturation, ImColor baseColor) {

    float baseH, baseS, baseV;
    ImGui::ColorConvertRGBtoHSV(baseColor.Value.x, baseColor.Value.y, baseColor.Value.z, baseH, baseS, baseV);

    double time = GetTickCount64() * 0.001 * speed;
    float wave = static_cast<float>(std::sin(time + index * 0.06 * 3.14159));

    float hue = baseH + wave * 0.15f;
    if (hue < 0.0f) hue += 1.0f;
    if (hue > 1.0f) hue -= 1.0f;

    return ImColor::HSV(hue, saturation, 1.0f);
}

ImColor BaseHUDElement::GetFadeColor(ImColor colorA, ImColor colorB, int index, float speed) {
    double time = GetTickCount64() * 0.002 * speed;
    float t = (std::sin(time + index * 0.3) + 1.0f) * 0.5f;
    return ImColor(
        ImLerp(colorA.Value.x, colorB.Value.x, t),
        ImLerp(colorA.Value.y, colorB.Value.y, t),
        ImLerp(colorA.Value.z, colorB.Value.z, t),
        colorA.Value.w
    );
}
