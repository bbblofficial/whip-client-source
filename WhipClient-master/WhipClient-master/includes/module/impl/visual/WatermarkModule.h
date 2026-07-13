#pragma once

#include "../../base/ListenedBaseModule.h"
#include "event/sub/Render2dEvent.h"
#include "event/sub/DispatchKeypressesEvent.h"
#include "util/KawaseBlur.h"
#include "ArrayListModule.h"

#include <string>
#include <atomic>
#include <chrono>

class WatermarkModule final : public ListenedBaseModule<WatermarkModule, ModuleType::WATERMARK, CategoryType::VISUAL> {
    friend class BaseModule;

    float       posNX      = 0.0f;
    float       posNY      = 0.0f;
    float       scale      = 1.8f;

    bool        dragging_  = false;
    ImVec2      dragOffset_{ 0.0f, 0.0f };
    bool        resizing_  = false;
    float       resizeBaseScale_ = 0.0f;
    float       resizeBaseMouseX_ = 0.0f;
    bool        blurEnabled = true;
    float       blurOpacity = 0.9f;
    bool        showVersion = true;
    bool        showPlayer  = true;
    bool        showServer  = true;
    bool        showFps     = true;

    std::string         cachedUsername_;
    std::string         cachedServerIp_;
    std::atomic<int>    cachedFps_{ 0 };
    long long           lastNameUpdate_ = 0;

    int       fpsFrameCount_ = 0;
    long long fpsTimer_      = 0;

    ImFont* wmFont_          = nullptr;
    ImFont* wmIconFont_      = nullptr;
    bool    fontInitialized_ = false;
    float   currentScale_    = -1.0f;
    void    initFont();

    [[nodiscard]] long long nowMs() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

public:
    WatermarkModule() : ListenedBaseModule(BindType::TOGGLE, 0) {}

    void onLoad() override;

    [[nodiscard]] bool shouldShowInArraylist() const override { return false; }

protected:
    void registerEvents() override;

private:
    void onTick(const OnRunTickEvent& event);
    void onRender2d(const Render2dEvent& event);
};
