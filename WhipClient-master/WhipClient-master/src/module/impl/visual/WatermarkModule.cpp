#include "../../../../includes/module/impl/visual/WatermarkModule.h"
#include "../../../../includes/wrapper/minecraft/client/Minecraft.h"
#include "../../../../includes/handler/MappingHandler.h"

#include <algorithm>
#include "setting/SettingMacros.h"
#include "gui/Gui.h"
#include "includes.h"
#include "Poppins-Bold.h"
#include "imgui_freetype.h"
#include "imgui_impl_opengl2.h"
#include "util/KawaseBlur.h"

void WatermarkModule::onLoad() {
    ListenedBaseModule::onLoad();

    REGISTER_FLOAT(posNX, 0.0f);
    REGISTER_FLOAT(posNY, 0.0f);

    FLOAT_SLIDER(scale, 1.8f, 0.5f, 3.0f);
    BOOL_SETTING_CONDITIONAL(blurEnabled, true);
    FLOAT_SLIDER_OPTIONAL(blurOpacity, 0.9f, 0.0f, 1.0f, SETTING_VISIBILITY(blurEnabled));
    BOOL_SETTING_CONDITIONAL(showVersion, true);
    BOOL_SETTING_CONDITIONAL(showPlayer, true);
    BOOL_SETTING_CONDITIONAL(showServer, true);
    BOOL_SETTING_CONDITIONAL(showFps, true);
}

void WatermarkModule::registerEvents() {
    subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
        onTick(event);
    });

    subscribe<Render2dEvent>([this](const Render2dEvent& event) {
        onRender2d(event);
    });
}

void WatermarkModule::onTick(const OnRunTickEvent& event) {
    if (!this->enable) return;

    const long long now = nowMs();
    if (cachedUsername_.empty() || now - lastNameUpdate_ >= 10000) {
        JNIEnv* env = event.getEnv();
        if (env) {
            Minecraft mc = Minecraft::getMinecraft(env);
            if (!mc.isNull()) {
                Session session = mc.getSession();
                if (!session.isNull()) {
                    JavaString js = session.getUsername();
                    if (!js.isNull()) {
                        std::string name = JavaString::jstringToString(env, (jstring)js.getObj());
                        if (!name.empty()) cachedUsername_ = name;
                    }
                }

                {
                    static jfieldID serverDataFid = nullptr;
                    static jfieldID serverIpFid = nullptr;
                    if (!serverDataFid) serverDataFid = JavaObject::getMappings()->getField("Minecraft#currentServerData");
                    if (!serverIpFid) serverIpFid = JavaObject::getMappings()->getField("ServerData#serverIP");

                    if (serverDataFid && serverIpFid) {
                        jobject serverData = env->GetObjectField(mc.getObj(), serverDataFid);
                        if (serverData) {
                            jstring ipStr = (jstring)env->GetObjectField(serverData, serverIpFid);
                            if (ipStr) {
                                std::string ip = JavaString::jstringToString(env, ipStr);
                                if (!ip.empty()) cachedServerIp_ = ip;
                                env->DeleteLocalRef(ipStr);
                            }
                            env->DeleteLocalRef(serverData);
                        } else {
                            cachedServerIp_.clear();
                        }
                    }
                    if (env->ExceptionCheck()) env->ExceptionClear();
                }
            }
        }
        lastNameUpdate_ = now;
    }
}

void WatermarkModule::initFont() {
    if (fontInitialized_) return;

    ImGuiIO& io = ImGui::GetIO();

    constexpr float MAX_SCALE = 3.0f;

    ImFontConfig cfg;
    cfg.FontBuilderFlags     = ImGuiFreeTypeBuilderFlags_MonoHinting | ImGuiFreeTypeBuilderFlags_Monochrome;
    cfg.FontDataOwnedByAtlas = false;

    wmFont_ = io.Fonts->AddFontFromMemoryTTF(
        const_cast<void*>(static_cast<const void*>(Poppins_Bold_compressed_data.data())),
        static_cast<int>(Poppins_Bold_compressed_data.size()),
        10.5f * MAX_SCALE, &cfg, io.Fonts->GetGlyphRangesCyrillic()
    );

    ImFontConfig icoCfg;
    icoCfg.FontBuilderFlags   = ImGuiFreeTypeBuilderFlags_MonoHinting;
    icoCfg.FontDataOwnedByAtlas = false;
    static const ImWchar icoRanges[] = { 0x0020, 0x007E, 0 };
    wmIconFont_ = io.Fonts->AddFontFromMemoryTTF(
        const_cast<void*>(static_cast<const void*>(icon_font.data())),
        static_cast<int>(icon_font.size()),
        10.5f * MAX_SCALE, &icoCfg, icoRanges
    );

    io.Fonts->Build();
    ImGui_ImplOpenGL2_DestroyFontsTexture();
    ImGui_ImplOpenGL2_CreateFontsTexture();

    fontInitialized_ = wmFont_ != nullptr;
}

void WatermarkModule::onRender2d(const Render2dEvent& event) {
    if (!this->enable) return;

    initFont();

    const long long now = nowMs();
    fpsFrameCount_++;
    if (now - fpsTimer_ >= 1000) {
        cachedFps_.store(fpsFrameCount_);
        fpsFrameCount_ = 0;
        fpsTimer_      = now;
    }

    ImDrawList* drawList = ImGui::GetBackgroundDrawList();
    if (!drawList) return;

    const ImGuiIO& io = ImGui::GetIO();
    const float sw = io.DisplaySize.x;
    const float sh = io.DisplaySize.y;

    ImFont* font = (fontInitialized_ && wmFont_ && wmFont_->ContainerAtlas &&
                    wmFont_->ContainerAtlas->TexID)
                   ? wmFont_ : ImGui::GetFont();
    if (!font) return;

    if (currentScale_ < 0.0f) currentScale_ = scale;
    const float dt = ImGui::GetIO().DeltaTime;
    currentScale_ += (scale - currentScale_) * (1.0f - expf(-18.0f * dt));
    if (fabsf(currentScale_ - scale) < 0.001f) currentScale_ = scale;
    const float s = currentScale_;

    const float FONT_SZ  = 10.5f * s;
    const float PAD_X    = 12.0f * s;
    const float PAD_Y    = 6.5f  * s;
    const float ROUNDING = 5.0f  * s;

    const ImU32 cAccent = draw->get_clr(ImVec4(clr->accent.Value.x, clr->accent.Value.y, clr->accent.Value.z, 1.0f));
    const ImU32 cWhite  = draw->get_clr(ImVec4(1.0f, 1.0f, 1.0f, 0.90f));
    const ImU32 cDim    = draw->get_clr(ImVec4(1.0f, 1.0f, 1.0f, 0.55f));
    const ImU32 cDot    = draw->get_clr(ImVec4(1.0f, 1.0f, 1.0f, 0.30f));

    struct Seg { std::string text; ImU32 color; };
    std::vector<Seg> segs;

    const bool hasIcon = fontInitialized_ && wmIconFont_ && wmIconFont_->ContainerAtlas && wmIconFont_->ContainerAtlas->TexID;
    const float iconW  = hasIcon ? wmIconFont_->CalcTextSizeA(FONT_SZ, FLT_MAX, 0.0f, "I").x : 0.0f;
    const float iconGap = hasIcon ? 5.0f * s : 0.0f;

    segs.push_back({ "Whip", cAccent });

    if (showVersion) {
        segs.push_back({ "  ·  ", cDot });
        segs.push_back({ "v0.7", cDim });
    }
    if (showPlayer && !cachedUsername_.empty()) {
        segs.push_back({ "  ·  ", cDot });
        segs.push_back({ cachedUsername_, cWhite });
    }
    if (showServer && !cachedServerIp_.empty()) {
        segs.push_back({ "  ·  ", cDot });
        segs.push_back({ cachedServerIp_, cDim });
    }
    if (showFps) {
        char fpsBuf[24];
        snprintf(fpsBuf, sizeof(fpsBuf), "%d fps", cachedFps_.load());
        segs.push_back({ "  ·  ", cDot });
        segs.push_back({ fpsBuf, cWhite });
    }

    float totalTextW = iconW + iconGap;
    for (const auto& s : segs)
        totalTextW += font->CalcTextSizeA(FONT_SZ, FLT_MAX, 0.0f, s.text.c_str()).x;

    const float barW = totalTextW + PAD_X * 2.0f;
    const float barH = FONT_SZ + PAD_Y * 2.0f;

    float barX = ImFloor(posNX * sw);
    float barY = ImFloor(posNY * sh);
    barX = ImFloor(std::max(0.0f, std::min(barX, sw - barW)));
    barY = ImFloor(std::max(0.0f, std::min(barY, sh - barH)));

    if (Gui::getInstance().isOpen() && !ImGui::GetIO().WantCaptureMouse) {
        const ImVec2 mouse = ImGui::GetMousePos();
        const bool   down  = ImGui::IsMouseDown(0);
        const bool   clicked = ImGui::IsMouseClicked(0);
        const ImRect rect(ImVec2(barX, barY), ImVec2(barX + barW, barY + barH));

        constexpr float HANDLE_SZ = 10.0f;
        const ImRect resizeRect(
            ImVec2(barX + barW - HANDLE_SZ, barY + barH - HANDLE_SZ),
            ImVec2(barX + barW, barY + barH));

        if (clicked) {
            if (resizeRect.Contains(mouse)) {
                resizing_ = true;
                resizeBaseScale_ = scale;
                resizeBaseMouseX_ = mouse.x;
                dragging_ = false;
            } else if (rect.Contains(mouse)) {
                dragging_   = true;
                dragOffset_ = ImVec2(barX - mouse.x, barY - mouse.y);
                resizing_ = false;
            } else {
                dragging_  = false;
                resizing_ = false;
            }
        }

        if (resizing_) {
            if (down) {
                float delta = (mouse.x - resizeBaseMouseX_) * 0.01f;
                scale = std::clamp(resizeBaseScale_ + delta, 0.5f, 3.0f);
            } else {
                resizing_ = false;
            }
        }

        if (dragging_) {
            if (down) {
                float nx = mouse.x + dragOffset_.x;
                float ny = mouse.y + dragOffset_.y;
                nx = std::max(0.0f, std::min(nx, sw - barW));
                ny = std::max(0.0f, std::min(ny, sh - barH));
                posNX = nx / sw;
                posNY = ny / sh;
                barX  = nx;
                barY  = ny;
            } else {
                dragging_ = false;
            }
        }
    }

    const ImVec2 bgMin(barX, barY);
    const ImVec2 bgMax(barX + barW, barY + barH);

    drawList->PushClipRect(ImVec2(0.0f, 0.0f), ImVec2(sw, sh), true);
    draw->shadow_rect(drawList, bgMin, bgMax,
        draw->get_clr(ImVec4(0.0f, 0.0f, 0.0f, 0.60f)),
        3.0f, ImVec2(0.0f, 1.0f), 0, ROUNDING);
    drawList->PopClipRect();

    if (blurEnabled) {
        static KawaseBlur::BlurParams bp;
        bp.strength     = 1.0f;
        bp.cornerRadius = ROUNDING;
        bp.rect         = { bgMin.x, bgMin.y, bgMax.x, bgMax.y };
        bp.tint         = { clr->child.Value.x, clr->child.Value.y, clr->child.Value.z, blurOpacity };
        drawList->AddCallback(KawaseBlur::renderDrawListBlur, &bp);
        drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
    }

    draw->rect_filled(drawList, bgMin, bgMax,
        draw->get_clr(ImVec4(clr->child.Value.x, clr->child.Value.y, clr->child.Value.z,
            blurEnabled ? 0.00f : blurOpacity)),
        ROUNDING, draw_flags_round_corners_all);

    draw->rect(drawList, bgMin, bgMax,
        draw->get_clr(ImVec4(clr->accent.Value.x, clr->accent.Value.y, clr->accent.Value.z, 0.12f)),
        ROUNDING, draw_flags_round_corners_all, 1.0f);

    draw->rect_filled(drawList,
        ImVec2(bgMin.x, bgMin.y + ROUNDING),
        ImVec2(bgMin.x + 2.0f * s, bgMax.y - ROUNDING),
        draw->get_clr(ImVec4(clr->accent.Value.x, clr->accent.Value.y, clr->accent.Value.z, 0.80f)),
        0.0f, 0);

    float cx = ImFloor(barX + PAD_X);
    const float cy = ImFloor(barY + PAD_Y);

    if (hasIcon) {
        const float iconCy = cy + (FONT_SZ - FONT_SZ) * 0.5f;

        drawList->AddText(wmIconFont_, FONT_SZ, ImVec2(cx, iconCy + 1.0f),
            draw->get_clr(ImVec4(0.0f, 0.0f, 0.0f, 0.45f)), "I");

        drawList->AddText(wmIconFont_, FONT_SZ, ImVec2(cx, iconCy), cAccent, "I");
        cx += iconW + iconGap;
    }

    for (const auto& s : segs) {

        drawList->AddText(font, FONT_SZ, ImVec2(cx, cy + 1.0f),
            draw->get_clr(ImVec4(0.0f, 0.0f, 0.0f, 0.45f)), s.text.c_str());

        drawList->AddText(font, FONT_SZ, ImVec2(cx, cy), s.color, s.text.c_str());
        cx = ImFloor(cx + font->CalcTextSizeA(FONT_SZ, FLT_MAX, 0.0f, s.text.c_str()).x);
    }

    if (Gui::getInstance().isOpen()) {
        const ImU32 col = (dragging_ || resizing_)
            ? IM_COL32(255, 165, 0, 220)
            : IM_COL32(100, 180, 255, 180);
        drawList->AddRect(
            ImVec2(bgMin.x - 2.0f, bgMin.y - 2.0f),
            ImVec2(bgMax.x + 2.0f, bgMax.y + 2.0f),
            col, ROUNDING + 2.0f, 0, 1.5f);

        const ImU32 handleCol = resizing_ ? IM_COL32(255, 165, 0, 255) : IM_COL32(100, 180, 255, 220);
        drawList->AddTriangleFilled(
            ImVec2(bgMax.x, bgMax.y),
            ImVec2(bgMax.x - 10.0f, bgMax.y),
            ImVec2(bgMax.x, bgMax.y - 10.0f),
            handleCol);
    }
}

REGISTER_MODULE(WatermarkModule, ModuleType::WATERMARK)
