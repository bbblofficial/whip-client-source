#include "../../../includes/hud/sub/ArraylistHUDElement.h"
#include "../../../includes/handler/ModuleHandler.h"
#include "../../../includes/hud/HUDElementRegistry.h"
#include "gui/includes.h"
#include "imgui_freetype.h"
#include "imgui_impl_opengl3.h"

#include <algorithm>
#include <chrono>
#include <cmath>

#include "imgui_impl_opengl2.h"
#include "util/ClientStrings.h"
#include "util/Debug.h"
#include "../../../includes/util/KawaseBlur.h"
#include "gui/Gui.h"

ArraylistHUDElement::ArraylistHUDElement()
    : BaseHUDElement(0, 0) {
    config = ModuleHandler::getInstance().getTypedModule<ArrayListModule, ModuleType::ARRAYLIST>();
    memset(sharedFlagsBuffer, 0, sizeof(sharedFlagsBuffer));
}

struct ModuleData {
    const char* name = nullptr;
    const char* flags = nullptr;
    float boundingBoxMin = 0;
    float boundingBoxMax = 0;
    float boundingBoxMinY = 0;
    float boundingBoxMaxY = 0;

    float boundingBarMin = 0;
    float boundingBarMax = 0;
    float boundingBarMinY = 0;
    float boundingBarMaxY = 0;

    ImVec2 renderPos = ImVec2(0, 0);

    ~ModuleData() { name = nullptr; flags = nullptr; memset(this, 0, sizeof(ModuleData)); }
};

static std::vector<KawaseBlur::BlurParams> blurParamsPool;
static KawaseBlur::BlurParams              titleBlurParams;

inline void secureStringClear(std::string& str) {
    if (str.capacity() > 0) {
        SecureZeroMemory(str.data(), str.capacity());
    }
    str.clear();
}

inline void secureBufferClear(char* buffer, size_t size) {
    if (buffer && size > 0) {
        SecureZeroMemory(buffer, size);
    }
}

void clearAllFormatBuffers() {
    ModuleHandler& manager = ModuleHandler::getInstance();
    std::vector<IModule*> modules = manager.getModules();

    for (const auto& module : modules) {
        auto renderer = dynamic_cast<IArraylistRenderer*>(module);
        if (renderer) {
            renderer->clearInstanceBuffer();
        }
    }

    for (auto& ptr : modules) {
        ptr = nullptr;
    }
    modules.clear();
    modules.shrink_to_fit();
}

void ArraylistHUDElement::initializeFonts() {
    ImGuiIO& io = GetIO();

    ImFontConfig cfg;
    cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_MonoHinting;
    cfg.FontDataOwnedByAtlas = false;

    cachedTitleFont = io.Fonts->AddFontFromMemoryTTF(
        const_cast<void*>(static_cast<const void*>(Poppins_Bold_compressed_data.data())),
        static_cast<int>(Poppins_Bold_compressed_data.size()),
        BASE_FONT_SIZE * TITLE_SCALE * MAX_SCALE,
        &cfg,
        io.Fonts->GetGlyphRangesCyrillic()
    );

    cachedHudFont = io.Fonts->AddFontFromMemoryTTF(
        const_cast<void*>(static_cast<const void*>(Poppins_Bold_compressed_data.data())),
        static_cast<int>(Poppins_Bold_compressed_data.size()),
        BASE_FONT_SIZE * MAX_SCALE,
        &cfg,
        io.Fonts->GetGlyphRangesCyrillic()
    );

    io.Fonts->Build();
    ImGui_ImplOpenGL2_DestroyFontsTexture();
    ImGui_ImplOpenGL2_CreateFontsTexture();

    fontsInitialized = (cachedTitleFont != nullptr && cachedHudFont != nullptr);
}

bool ArraylistHUDElement::ensureFontsValid() {
    if (!fontsInitialized || cachedTitleFont == nullptr || cachedHudFont == nullptr) {
        initializeFonts();
        return fontsInitialized;
    }

    if (cachedTitleFont->ContainerAtlas == nullptr || cachedHudFont->ContainerAtlas == nullptr) {
        fontsInitialized = false;
        initializeFonts();
        return fontsInitialized;
    }

    if (cachedTitleFont->ContainerAtlas->TexID == nullptr ||
        cachedHudFont->ContainerAtlas->TexID == nullptr) {
        fontsInitialized = false;
        initializeFonts();
        return fontsInitialized;
    }

    return true;
}

inline void ArraylistHUDElement::drawTextWithShadow(
    ImDrawList* drawList,
    const ImFont* font,
    const float fontSize,
    const ImVec2& pos,
    const ImColor& color,
    const char* text
) const
{
    if (ArrayListModule::textShadows) {
        const ImDrawListFlags backup_flags = drawList->Flags;
        drawList->Flags &= ~ImDrawListFlags_AntiAliasedLines;
        drawList->Flags &= ~ImDrawListFlags_AntiAliasedLinesUseTex;
        drawList->Flags &= ~ImDrawListFlags_AntiAliasedFill;

        const float shadowOff = BASE_SHADOW_OFFSET * (currentScale_ > 0.0f ? currentScale_ : 1.0f);
        const ImVec2 basePos = ImFloor(pos);
        const ImVec2 finalPos = ImFloor(ImVec2(
            basePos.x + shadowOff,
            basePos.y + shadowOff
        ));

        drawList->AddText(
            font,
            fontSize,
            ImVec2(finalPos.x, finalPos.y),
            draw->get_clr(ArrayListModule::shadowColor),
            text,
            nullptr,
            0.0f
        );

        drawList->Flags = backup_flags;
    }

    drawList->AddText(
        font,
        fontSize,
        pos,
        draw->get_clr(color),
        text,
        nullptr,
        0.0f
    );
}

static std::vector<KawaseBlur::BlurParams> guiBlurPool;

void renderGuiBased(ArrayListModule* config, ImFont* hudFont, float BASE_FONT_SIZE, float SHADOW_OFFSET) {
    ModuleHandler& manager = ModuleHandler::getInstance();
    std::vector<IModule*> modules = manager.getModules();
    ImGuiIO& io = GetIO();
    const float sw = io.DisplaySize.x;
    const float sh = io.DisplaySize.y;

    struct Entry { const char* name; const char* flags; float totalW; };
    std::vector<Entry> entries;

    for (auto* module : modules) {
        auto* renderer = dynamic_cast<IArraylistRenderer*>(module);
        if (!renderer || (!module->isEnabled() && !renderer->forceRender()) || !renderer->shouldShowInArraylist()) continue;
        const char* name = renderer->getDisplayName();
        if (!name || strlen(name) == 0) continue;
        const char* flags = renderer->getDisplayFlags();

        char lcN[128] = {}; char lcF[128] = {};
        const char* measName  = name;
        const char* measFlags = flags;
        if (ArrayListModule::lowerCase) {
            strncpy(lcN, name, sizeof(lcN) - 1);
            for (size_t i = 0; lcN[i]; i++) if (lcN[i] >= 'A' && lcN[i] <= 'Z') lcN[i] += ('a'-'A');
            measName = lcN;
            if (flags && flags[0]) {
                strncpy(lcF, flags, sizeof(lcF) - 1);
                for (size_t i = 0; lcF[i]; i++) if (lcF[i] >= 'A' && lcF[i] <= 'Z') lcF[i] += ('a'-'A');
                measFlags = lcF;
            }
        }

        float nw = hudFont->CalcTextSizeA(BASE_FONT_SIZE, FLT_MAX, 0, measName).x;
        float fw = 0;
        if (measFlags && strlen(measFlags) > 0) {
            const char* t = measFlags; while (*t == ' ') t++;
            if (strlen(t) > 0) fw = hudFont->CalcTextSizeA(BASE_FONT_SIZE, FLT_MAX, 0, t).x + 5.0f;
        }
        entries.push_back({ name, flags, nw + fw });
    }

    for (auto& p : modules) p = nullptr;
    modules.clear();
    if (entries.empty()) return;

    std::ranges::sort(entries, [](const Entry& a, const Entry& b) { return a.totalW > b.totalW; });

    const float PAD_X    = ArrayListModule::paddingX + 3.0f;
    const float PAD_Y    = ArrayListModule::paddingY + 1.0f;
    const float BAR_W    = ArrayListModule::bar ? 2.5f : 0.0f;
    const float ROUND    = 3.0f;
    const float GAP      = 1.0f;
    const float LINE_H   = BASE_FONT_SIZE + PAD_Y * 2.0f;

    const float anchor   = ArrayListModule::posNX * sw;
    const bool  isRight  = (ArrayListModule::posNX >= 0.5f);
    float       startY   = ArrayListModule::posNY * sh + 5.0f;

    ImDrawList* drawList = GetBackgroundDrawList();

    if (ArrayListModule::blurEnabled && entries.size() > guiBlurPool.size())
        guiBlurPool.resize(entries.size());

    static auto startTime = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime).count();

    float curY = startY;
    int idx = 0;

    for (const auto& e : entries) {
        const float rowW = e.totalW + PAD_X * 2.0f + BAR_W;
        const float rowX = isRight ? (anchor - rowW) : anchor;

        const ImVec2 rowMin(rowX, curY);
        const ImVec2 rowMax(rowX + rowW, curY + LINE_H);

        int roundFlags = 0;
        if (idx == 0 && isRight)
            roundFlags = draw_flags_round_corners_top_left;
        else if (idx == 0 && !isRight)
            roundFlags = draw_flags_round_corners_top_right;
        if (idx == (int)entries.size() - 1) {
            if (isRight) roundFlags |= draw_flags_round_corners_bottom_left | draw_flags_round_corners_bottom_right;
            else         roundFlags |= draw_flags_round_corners_bottom_left | draw_flags_round_corners_bottom_right;
        }
        if (roundFlags == 0) roundFlags = draw_flags_round_corners_none;

        float wave = fmod((elapsed % 3000) / 3000.0f + (idx * 0.08f), 1.0f);
        float m = (sinf(wave * 6.28318f) + 1.0f) * 0.5f * 0.30f;
        ImVec4 modAccent(
            clr->accent.Value.x + (1.0f - clr->accent.Value.x) * m,
            clr->accent.Value.y + (1.0f - clr->accent.Value.y) * m,
            clr->accent.Value.z + (1.0f - clr->accent.Value.z) * m,
            1.0f);

        if (ArrayListModule::blurEnabled) {
            KawaseBlur::BlurParams& bp = guiBlurPool[idx];
            bp.strength = 1.0f;
            bp.cornerRadius = ROUND;
            bp.rect = { rowMin.x, rowMin.y, rowMax.x, rowMax.y };
            bp.tint = { clr->child.Value.x, clr->child.Value.y, clr->child.Value.z, ArrayListModule::blurOpacity };
            drawList->PushClipRect(rowMin, rowMax, true);
            drawList->AddCallback(KawaseBlur::renderDrawListBlur, &bp);
            drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
            drawList->PopClipRect();
        }

        draw->rect_filled(drawList, rowMin, rowMax,
            draw->get_clr(ImVec4(clr->child.Value.x, clr->child.Value.y, clr->child.Value.z,
                ArrayListModule::blurEnabled ? 0.00f : ArrayListModule::blurOpacity)),
            ROUND, roundFlags);

        draw->rect(drawList, rowMin, rowMax,
            draw->get_clr(ImVec4(clr->accent.Value.x, clr->accent.Value.y, clr->accent.Value.z, 0.06f)),
            ROUND, roundFlags, 1.0f);

        if (ArrayListModule::bar) {
            ImVec2 barMin, barMax;
            if (isRight) {
                barMin = ImVec2(rowMax.x - BAR_W, rowMin.y);
                barMax = ImVec2(rowMax.x, rowMax.y);
            } else {
                barMin = ImVec2(rowMin.x, rowMin.y);
                barMax = ImVec2(rowMin.x + BAR_W, rowMax.y);
            }
            draw->rect_filled(drawList, barMin, barMax, draw->get_clr(modAccent), ROUND, roundFlags);
        }

        float textX = isRight ? (rowX + PAD_X) : (rowX + PAD_X + BAR_W);
        float textY = curY + PAD_Y;

        char lcNameBuf[128] = {};
        char lcFlagBuf[128] = {};
        const char* nameText = e.name;
        const char* flagText = e.flags ? e.flags : "";
        if (ArrayListModule::lowerCase) {
            strncpy(lcNameBuf, e.name, sizeof(lcNameBuf) - 1);
            for (size_t i = 0; lcNameBuf[i]; i++)
                if (lcNameBuf[i] >= 'A' && lcNameBuf[i] <= 'Z') lcNameBuf[i] += ('a' - 'A');
            nameText = lcNameBuf;
            if (e.flags && e.flags[0]) {
                strncpy(lcFlagBuf, e.flags, sizeof(lcFlagBuf) - 1);
                for (size_t i = 0; lcFlagBuf[i]; i++)
                    if (lcFlagBuf[i] >= 'A' && lcFlagBuf[i] <= 'Z') lcFlagBuf[i] += ('a' - 'A');
                flagText = lcFlagBuf;
            }
        }
        ImU32 nameCol = draw->get_clr(modAccent);
        ImVec2 namePos = ImFloor(ImVec2(textX, textY));
        if (ArrayListModule::textShadows) {
            drawList->AddText(hudFont, BASE_FONT_SIZE,
                ImFloor(ImVec2(namePos.x + SHADOW_OFFSET, namePos.y + SHADOW_OFFSET)),
                draw->get_clr(ArrayListModule::shadowColor), nameText);
        }
        drawList->AddText(hudFont, BASE_FONT_SIZE, namePos, nameCol, nameText);

        if (flagText && *flagText) {
            const char* trimmed = flagText;
            while (*trimmed == ' ') trimmed++;
            if (strlen(trimmed) > 0) {
                float nameW = hudFont->CalcTextSizeA(BASE_FONT_SIZE, FLT_MAX, 0, nameText).x;
                ImVec2 flagPos = ImFloor(ImVec2(textX + nameW + 5.0f, textY));
                ImU32 flagCol = draw->get_clr(ArrayListModule::delayColor);
                if (ArrayListModule::textShadows) {
                    drawList->AddText(hudFont, BASE_FONT_SIZE,
                        ImFloor(ImVec2(flagPos.x + SHADOW_OFFSET, flagPos.y + SHADOW_OFFSET)),
                        draw->get_clr(ArrayListModule::shadowColor), trimmed);
                }
                drawList->AddText(hudFont, BASE_FONT_SIZE, flagPos, flagCol, trimmed);
            }
        }

        curY += LINE_H + GAP;
        idx++;
    }

    if (Gui::getInstance().isOpen() && !io.WantCaptureMouse) {
        static bool gbDragging = false;
        static ImVec2 gbDragOff;
        const ImVec2 mouse = ImGui::GetMousePos();
        const bool down = ImGui::IsMouseDown(0);
        const bool clicked = ImGui::IsMouseClicked(0);

        const float dragMinX = isRight ? (anchor - 200.0f) : anchor;
        const float dragMaxX = isRight ? anchor : (anchor + 200.0f);
        const bool inList = mouse.x >= dragMinX && mouse.x <= dragMaxX
                         && mouse.y >= startY && mouse.y <= curY;

        if (clicked && inList) {
            gbDragging = true;
            gbDragOff = ImVec2(anchor - mouse.x, startY - mouse.y);
        }
        if (!down) gbDragging = false;
        if (gbDragging && down) {
            float newAnchor = std::max(0.0f, std::min(mouse.x + gbDragOff.x, sw));
            float newTop = std::max(0.0f, std::min(mouse.y + gbDragOff.y, sh * 0.9f));
            ArrayListModule::posNX = newAnchor / sw;
            ArrayListModule::posNY = (newTop - 5.0f) / sh;
        }

        if (curY > startY) {
            drawList->AddRect(
                ImVec2(dragMinX - 2, startY - 2),
                ImVec2(dragMaxX + 2, curY + 2),
                gbDragging ? IM_COL32(255, 165, 0, 220) : IM_COL32(100, 180, 255, 180),
                ROUND + 2, 0, 1.5f);
        }
    }

    for (auto& e : entries) { e.name = nullptr; e.flags = nullptr; }
}

void ArraylistHUDElement::onRender() {
    if (!config || !config->enable) return;

    if (!ensureFontsValid()) {
        return;
    }

    if (currentScale_ < 0.0f) currentScale_ = ArrayListModule::scale;
    const float dt = GetIO().DeltaTime;
    currentScale_ += (ArrayListModule::scale - currentScale_) * (1.0f - expf(-18.0f * dt));
    if (fabsf(currentScale_ - ArrayListModule::scale) < 0.001f) currentScale_ = ArrayListModule::scale;
    const float s = currentScale_;

    const float FONT_SIZE = BASE_FONT_SIZE * s;
    const float LINE_SPACING = BASE_LINE_SPACING * s;
    const float SHADOW_OFFSET = BASE_SHADOW_OFFSET * s;
    const float BAR_WIDTH = BASE_BAR_WIDTH * s;
    const float ROUNDING = BASE_ROUNDING * s;

    const bool isGuiBased = (ArrayListModule::colorMode == ArrayListModule::GUI_BASED);

    ImFont* titleFont = cachedTitleFont;
    ImFont* hudFont = cachedHudFont;

    ModuleHandler& manager = ModuleHandler::getInstance();
    std::vector<IModule*> modules = manager.getModules();
    std::vector<std::pair<IModule*, ModuleData>> activeModules;
    ImGuiIO& io = GetIO();
    const float screenWidth  = io.DisplaySize.x;
    const float screenHeight = io.DisplaySize.y;

    const float listAnchor   = ArrayListModule::posNX * screenWidth;
    const bool  isRight      = (ArrayListModule::posNX >= 0.5f);
    const float barSlotWidth = ArrayListModule::bar ? BAR_WIDTH : 0.0f;
    float currentY = ArrayListModule::posNY * screenHeight + 5.0f;
    const float startY = currentY;

    for (const auto& module : modules) {
        auto renderer = dynamic_cast<IArraylistRenderer*>(module);
        if (!renderer) {
            continue;
        }

        if (module->isEnabled() || renderer->forceRender()) {
            if (!renderer->shouldShowInArraylist()) {
                continue;
            }

            ModuleData data;
            data.name = renderer->getDisplayName();
            data.flags = renderer->getDisplayFlags();

            if (!data.name || strlen(data.name) == 0) {
                continue;
            }

            activeModules.emplace_back(module, std::move(data));
        }
    }

    for (auto& ptr : modules) {
        ptr = nullptr;
    }
    modules.clear();
    modules.shrink_to_fit();

    std::ranges::sort(activeModules,
                      [hudFont, FONT_SIZE](const auto& a, const auto& b) {
                          const char* nameA = a.second.name ? a.second.name : "";
                          const char* flagsA = a.second.flags ? a.second.flags : "";
                          const char* nameB = b.second.name ? b.second.name : "";
                          const char* flagsB = b.second.flags ? b.second.flags : "";

                          if (hudFont == nullptr || hudFont->ContainerAtlas == nullptr) {
                              return false;
                          }

                          ImVec2 nameASize = hudFont->CalcTextSizeA(FONT_SIZE, FLT_MAX, 0.0f, nameA);
                          ImVec2 flagsASize = hudFont->CalcTextSizeA(FONT_SIZE, FLT_MAX, 0.0f, flagsA);
                          ImVec2 nameBSize = hudFont->CalcTextSizeA(FONT_SIZE, FLT_MAX, 0.0f, nameB);
                          ImVec2 flagsBSize = hudFont->CalcTextSizeA(FONT_SIZE, FLT_MAX, 0.0f, flagsB);

                          float totalA = nameASize.x + flagsASize.x + (flagsASize.x > 0 ? 5.0f : 0.0f);
                          float totalB = nameBSize.x + flagsBSize.x + (flagsBSize.x > 0 ? 5.0f : 0.0f);

                          return totalA > totalB;
                      });

    ImDrawList* drawList = GetBackgroundDrawList();
    float modulePosition = currentY / io.DisplaySize.y;
    float contentMinX = listAnchor;
    float contentMaxX = listAnchor;

    if (ArrayListModule::blurEnabled && activeModules.size() > blurParamsPool.size()) {
        blurParamsPool.resize(activeModules.size());
    }

    static auto startTime = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count();

    if (ArrayListModule::showTitle && !isGuiBased) {
    ImColor titleColor;
    if (!ArrayListModule::titleCustomColor) {
        if (ArrayListModule::colorMode == ArrayListModule::STATIC) {
            titleColor = ArrayListModule::mainColor;
        } else if (ArrayListModule::colorMode == ArrayListModule::RAINBOW) {
            float hue = fmod((elapsed % 3000) / 3000.0f, 1.0f);
            float r, g, b;
            ImGui::ColorConvertHSVtoRGB(hue, 1.0f, 1.0f, r, g, b);
            titleColor = ImColor(r, g, b, 1.0f);
        } else if (ArrayListModule::colorMode == ArrayListModule::FADE) {
            auto col = ArrayListModule::mainColor.Value;
            titleColor = ImColor(col.x, col.y, col.z, col.w);
        } else {
            float wave = fmod((elapsed % 3000) / 3000.0f, 1.0f);
            float m = (sin(wave * 6.28318f) + 1.0f) * 0.5f * 0.35f;
            auto flColor = ArrayListModule::flowColor.Value;
            titleColor = ImColor(flColor.x + (1.0f - flColor.x) * m, flColor.y + (1.0f - flColor.y) * m, flColor.z + (1.0f - flColor.z) * m, flColor.w);
        }
    } else if (ArrayListModule::titleColorMode == 0) {
        titleColor = ArrayListModule::titleMainColor;
    } else if (ArrayListModule::titleColorMode == 1) {
        float hue = fmod((elapsed % 3000) / 3000.0f, 1.0f);
        float r, g, b;
        ImGui::ColorConvertHSVtoRGB(hue, 1.0f, 1.0f, r, g, b);
        titleColor = ImColor(r, g, b, 1.0f);
    } else {
        float wave = fmod((elapsed % 3000) / 3000.0f, 1.0f);
        float m = (sin(wave * 6.28318f) + 1.0f) * 0.5f * 0.35f;
        auto flColor = ArrayListModule::titleFlowColor.Value;
        titleColor = ImColor(flColor.x + (1.0f - flColor.x) * m, flColor.y + (1.0f - flColor.y) * m, flColor.z + (1.0f - flColor.z) * m, flColor.w);
    }

    const float titleFontSz  = FONT_SIZE * TITLE_SCALE;
    const float TITLE_PAD_X  = ArrayListModule::paddingX * s;
    const float TITLE_PAD_Y  = (ArrayListModule::paddingY + 1.5f) * s;
    const float barSlot      = barSlotWidth;

    const char* windowTitle = Strings::windowTitle();

    gui->push_font(titleFont);
    ImVec2 titleTextSize = titleFont->CalcTextSizeA(titleFontSz, FLT_MAX, 0.0f, windowTitle);
    gui->pop_font();

    const float pillW = titleTextSize.x + TITLE_PAD_X * 2.0f + barSlot;
    const float pillH = titleTextSize.y + TITLE_PAD_Y * 2.0f;

    const float pillX = isRight ? (listAnchor - pillW) : listAnchor;
    const float pillY = currentY;

    const ImVec2 pillMin(pillX, pillY);
    const ImVec2 pillMax(pillX + pillW, pillY + pillH);

    const float cx = pillX + TITLE_PAD_X;
    const float cy = pillY + TITLE_PAD_Y;

    gui->push_font(titleFont);
    drawTextWithShadow(drawList, titleFont, titleFontSz,
        ImVec2(cx, cy), titleColor, windowTitle);
    gui->pop_font();

    currentY += pillH + LINE_SPACING;

    }

    gui->push_font(hudFont);

    int waveDelay = 0;
    int moduleIndex = 0;

    for (auto &[module, data]: activeModules) {
        char nameBuffer[64];
        char flagBuffer[64];

        secureBufferClear(nameBuffer, sizeof(nameBuffer));
        secureBufferClear(flagBuffer, sizeof(flagBuffer));

        const char* nameText = "";
        const char* flagText = "";

        if (ArrayListModule::lowerCase) {
            const char* srcName = data.name ? data.name : "";
            const char* srcFlags = data.flags ? data.flags : "";

            size_t nameLen = strlen(srcName);
            size_t flagLen = strlen(srcFlags);

            if (nameLen > 0 && nameLen < sizeof(nameBuffer) - 1) {
                strncpy(nameBuffer, srcName, sizeof(nameBuffer) - 1);
                nameBuffer[sizeof(nameBuffer) - 1] = '\0';

                for (size_t i = 0; i < nameLen && nameBuffer[i]; i++) {
                    if (nameBuffer[i] >= 'A' && nameBuffer[i] <= 'Z') {
                        nameBuffer[i] = nameBuffer[i] + ('a' - 'A');
                    }
                }
                nameText = nameBuffer;
            }

            if (flagLen > 0 && flagLen < sizeof(flagBuffer) - 1) {
                while (*srcFlags == ' ' && *srcFlags != '\0') {
                    srcFlags++;
                    flagLen--;
                }

                if (flagLen > 0) {
                    memcpy(flagBuffer, srcFlags, flagLen);
                    flagBuffer[flagLen] = '\0';

                    for (size_t i = 0; i < flagLen && flagBuffer[i]; i++) {
                        if (flagBuffer[i] >= 'A' && flagBuffer[i] <= 'Z') {
                            flagBuffer[i] = flagBuffer[i] + ('a' - 'A');
                        }
                    }
                    flagText = flagBuffer;
                }
            }
        } else {
            nameText = data.name ? data.name : "";

            if (data.flags) {
                const char* trimmedFlags = data.flags;
                while (*trimmedFlags == ' ' && *trimmedFlags != '\0') {
                    trimmedFlags++;
                }
                flagText = trimmedFlags;
            } else {
                flagText = "";
            }
        }

        const float padX = ArrayListModule::paddingX * s;
        const float padY = ArrayListModule::paddingY * s;

        ImVec2 nameSize = hudFont->CalcTextSizeA(FONT_SIZE, FLT_MAX, 0.0f, nameText);
        ImVec2 flagSize = (flagText && strlen(flagText) > 0) ? hudFont->CalcTextSizeA(FONT_SIZE, FLT_MAX, 0.0f, flagText) : ImVec2(0, 0);

        float spaceWidth = flagSize.x > 0 ? 5.0f * s : 0;
        ImVec2 textSize = ImVec2(nameSize.x + spaceWidth + flagSize.x, nameSize.y);

        const float boxW = textSize.x + padX * 2.0f + barSlotWidth;
        float x = isRight ? (listAnchor - boxW) : listAnchor;

        if (x < contentMinX) contentMinX = x;
        if (x + boxW > contentMaxX) contentMaxX = x + boxW;

        const auto boundingBox = ImRect(
            ImVec2(x, currentY + 1),
            ImVec2(x + textSize.x + padX * 2 + (ArrayListModule::bar ? BAR_WIDTH : 0),
                currentY + textSize.y + padY * 2 - 0.7f)
        );

        const auto boundingBar = ImRect(
            ImVec2(x, currentY),
            ImVec2(x + textSize.x + padX * 2 + (ArrayListModule::bar ? BAR_WIDTH : 0),
                currentY + textSize.y + padY * 2)
        );

        if (data.boundingBoxMin == 0) data.boundingBoxMin = boundingBox.Min.x;
        if (data.boundingBoxMax == 0) data.boundingBoxMax = boundingBox.Max.x;
        if (data.boundingBoxMinY == 0) data.boundingBoxMinY = boundingBox.Min.y;
        if (data.boundingBoxMaxY == 0) data.boundingBoxMaxY = boundingBox.Max.y;

        data.boundingBoxMin = ImLerp(data.boundingBoxMin, boundingBox.Min.x, io.DeltaTime * 7.0f);
        data.boundingBoxMax = ImLerp(data.boundingBoxMax, boundingBox.Max.x, io.DeltaTime * 7.0f);
        data.boundingBoxMinY = ImLerp(data.boundingBoxMinY, boundingBox.Min.y, io.DeltaTime * 7.0f);
        data.boundingBoxMaxY = ImLerp(data.boundingBoxMaxY, boundingBox.Max.y, io.DeltaTime * 7.0f);

        if (data.boundingBarMin == 0) data.boundingBarMin = boundingBar.Min.x;
        if (data.boundingBarMax == 0) data.boundingBarMax = boundingBar.Max.x;
        if (data.boundingBarMinY == 0) data.boundingBarMinY = boundingBar.Min.y;
        if (data.boundingBarMaxY == 0) data.boundingBarMaxY = boundingBar.Max.y;

        data.boundingBarMin = ImLerp(data.boundingBarMin, boundingBar.Min.x, io.DeltaTime * 7.0f);
        data.boundingBarMax = ImLerp(data.boundingBarMax, boundingBar.Max.x, io.DeltaTime * 7.0f);
        data.boundingBarMinY = ImLerp(data.boundingBarMinY, boundingBar.Min.y, io.DeltaTime * 7.0f);
        data.boundingBarMaxY = ImLerp(data.boundingBarMaxY, boundingBar.Max.y, io.DeltaTime * 7.0f);

        const float textOffsetX = padX + (isRight ? 0.0f : (ArrayListModule::bar ? BAR_WIDTH : 0.0f));
        ImVec2 textPos(x + textOffsetX, currentY + padY);
        if (data.renderPos.x == 0 && data.renderPos.y == 0) data.renderPos = textPos;
        data.renderPos = ImLerp(data.renderPos, textPos, io.DeltaTime * 7.0f);

        ImColor moduleColor;
        ImColor flagNameColor = ImColor(1.0f, 1.0f, 1.0f, 1.0f);

        int totalModules = static_cast<int>(activeModules.size());

        if (ArrayListModule::colorMode == ArrayListModule::STATIC) {
            moduleColor = ArrayListModule::mainColor;
        } else if (ArrayListModule::colorMode == ArrayListModule::RAINBOW) {
            float hue = fmod((elapsed % 3000) / 3000.0f + (moduleIndex * 0.05f), 1.0f);
            float r, g, b;
            ImGui::ColorConvertHSVtoRGB(hue, 1.0f, 1.0f, r, g, b);
            moduleColor = ImColor(r, g, b, 1.0f);
        } else if (ArrayListModule::colorMode == ArrayListModule::FADE) {
            float t = (float)moduleIndex / std::max(1.0f, (float)totalModules - 1);
            if (ArrayListModule::fadeReversed) t = 1.0f - t;
            auto col = ArrayListModule::mainColor.Value;
            float factor = (1.0f - t * 0.5f);
            moduleColor = ImColor(col.x * factor, col.y * factor, col.z * factor, col.w);
        } else if (ArrayListModule::colorMode == ArrayListModule::GUI_BASED) {
            float wave = fmod((elapsed % 3000) / 3000.0f + (moduleIndex * 0.08f), 1.0f);
            float m = (sinf(wave * 6.28318f) + 1.0f) * 0.5f * 0.30f;
            moduleColor = ImColor(
                clr->accent.Value.x + (1.0f - clr->accent.Value.x) * m,
                clr->accent.Value.y + (1.0f - clr->accent.Value.y) * m,
                clr->accent.Value.z + (1.0f - clr->accent.Value.z) * m,
                1.0f);
            flagNameColor = ArrayListModule::delayColor;
        } else {
            float wave = fmod((elapsed % 3000) / 3000.0f + (moduleIndex * 0.15f), 1.0f);
            float m = (sin(wave * 6.28318f) + 1.0f) * 0.5f * 0.35f;
            auto flColor = ArrayListModule::flowColor.Value;
            moduleColor = ImColor(flColor.x + (1.0f - flColor.x) * m, flColor.y + (1.0f - flColor.y) * m, flColor.z + (1.0f - flColor.z) * m, flColor.w);
        }

        if (ArrayListModule::drawBox || isGuiBased) {
            const auto boxBoundingBox = ImRect(
                ImVec2(data.boundingBoxMin, data.boundingBoxMinY),
                ImVec2(data.boundingBoxMax, data.boundingBoxMaxY)
            );

            int roundFlags = draw_flags_round_corners_all;
            if (isGuiBased) {
                roundFlags = 0;
                if (moduleIndex == 0 && isRight)
                    roundFlags = draw_flags_round_corners_top_left;
                else if (moduleIndex == 0 && !isRight)
                    roundFlags = draw_flags_round_corners_top_right;
                if (moduleIndex == static_cast<int>(activeModules.size()) - 1)
                    roundFlags |= draw_flags_round_corners_bottom_left | draw_flags_round_corners_bottom_right;
                if (roundFlags == 0) roundFlags = draw_flags_round_corners_none;
            }

            if (ArrayListModule::glowEnabled && !isGuiBased) {
                ImU32 glowColor = IM_COL32(
                    (int)(moduleColor.Value.x * 255),
                    (int)(moduleColor.Value.y * 255),
                    (int)(moduleColor.Value.z * 255),
                    (int)(ArrayListModule::glowAlpha * 255));
                draw->shadow_rect(drawList,
                    boxBoundingBox.Min, boxBoundingBox.Max,
                    glowColor, ArrayListModule::glowSize,
                    ImVec2(0, 0), 0, ROUNDING);
            }

            if (ArrayListModule::blurEnabled) {
                KawaseBlur::BlurParams& bp = blurParamsPool[moduleIndex];
                bp.strength = 1.0f;
                bp.cornerRadius = ROUNDING;
                bp.rect = { boxBoundingBox.Min.x, boxBoundingBox.Min.y, boxBoundingBox.Max.x, boxBoundingBox.Max.y };
                bp.tint = { clr->child.Value.x, clr->child.Value.y, clr->child.Value.z, ArrayListModule::blurOpacity };

                drawList->PushClipRect(boxBoundingBox.Min, boxBoundingBox.Max, true);
                drawList->AddCallback(KawaseBlur::renderDrawListBlur, &bp);
                drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
                drawList->PopClipRect();
            }

            draw->rect_filled(drawList, boxBoundingBox.Min, boxBoundingBox.Max,
                draw->get_clr(ImVec4(clr->child.Value.x, clr->child.Value.y, clr->child.Value.z,
                    ArrayListModule::blurEnabled ? 0.00f : ArrayListModule::blurOpacity)),
                ROUNDING, roundFlags);

            if (isGuiBased) {
                draw->rect(drawList, boxBoundingBox.Min, boxBoundingBox.Max,
                    draw->get_clr(ImVec4(clr->accent.Value.x, clr->accent.Value.y, clr->accent.Value.z, 0.06f)),
                    ROUNDING, roundFlags, 1.0f);
            }
        }

        ImVec2 currentTextPos = data.renderPos;
        drawTextWithShadow(drawList, hudFont, FONT_SIZE,
            currentTextPos, moduleColor, nameText);

        if (flagText && strlen(flagText) > 0) {
            ImVec2 actualNameSize = hudFont->CalcTextSizeA(FONT_SIZE, FLT_MAX, 0.0f, nameText);

            float adjustedSpacing = spaceWidth + SHADOW_OFFSET;
            float flagPosX = currentTextPos.x + actualNameSize.x + adjustedSpacing;

            drawTextWithShadow(drawList, hudFont, FONT_SIZE,
                ImVec2(flagPosX, currentTextPos.y),
                flagNameColor,
                flagText);
        }

        if (ArrayListModule::bar) {
            const auto barBoundingBar = isRight
                ? ImRect(ImVec2(data.boundingBarMax - BAR_WIDTH, data.boundingBarMinY),
                         ImVec2(data.boundingBarMax,             data.boundingBarMaxY))
                : ImRect(ImVec2(data.boundingBarMin,             data.boundingBarMinY),
                         ImVec2(data.boundingBarMin + BAR_WIDTH, data.boundingBarMaxY));
            draw->rect_filled(drawList, barBoundingBar.Min, barBoundingBar.Max,
                draw->get_clr(moduleColor), ROUNDING, draw_flags_round_corners_all);
        }

        currentY += textSize.y + LINE_SPACING;
        moduleIndex++;

        secureBufferClear(nameBuffer, sizeof(nameBuffer));
        secureBufferClear(flagBuffer, sizeof(flagBuffer));

        nameText = "";
        flagText = "";

        data.name = nullptr;
        data.flags = nullptr;
    }

    gui->pop_font();

    if (Gui::getInstance().isOpen() && currentY > startY) {
        static bool   alDragging = false;
        static ImVec2 alDragOff;

        const ImVec2 mouse   = ImGui::GetMousePos();
        const bool   down    = ImGui::IsMouseDown(0);
        const bool   clicked = ImGui::IsMouseClicked(0);

        const ImVec2 editMin(contentMinX - 2.0f, startY - 2.0f);
        const ImVec2 editMax(contentMaxX + 2.0f, currentY + 2.0f);

        const bool inList = mouse.x >= contentMinX && mouse.x <= contentMaxX
                         && mouse.y >= startY && mouse.y <= currentY;

        constexpr float HANDLE_SZ = 14.0f;
        const ImRect resizeRect = isRight
            ? ImRect(ImVec2(editMin.x, editMax.y - HANDLE_SZ), ImVec2(editMin.x + HANDLE_SZ, editMax.y))
            : ImRect(ImVec2(editMax.x - HANDLE_SZ, editMax.y - HANDLE_SZ), editMax);

        if (clicked) {
            if (resizeRect.Contains(mouse)) {
                resizing_ = true;
                resizeBaseScale_ = ArrayListModule::scale;
                resizeBaseMouseX_ = mouse.x;
                alDragging = false;
            } else if (inList) {
                alDragging = true;
                alDragOff  = ImVec2(listAnchor - mouse.x, startY - mouse.y);
                resizing_ = false;
            } else {
                alDragging = false;
                resizing_ = false;
            }
        }

        if (resizing_) {
            if (down) {
                float delta = (mouse.x - resizeBaseMouseX_) * (isRight ? -0.01f : 0.01f);
                ArrayListModule::scale = std::clamp(resizeBaseScale_ + delta, 0.5f, 3.0f);
            } else {
                resizing_ = false;
            }
        }

        if (!down) alDragging = false;
        if (alDragging && down) {
            float newAnchor = mouse.x + alDragOff.x;
            newAnchor = std::max(0.0f, std::min(newAnchor, screenWidth));
            float newTop = std::max(0.0f, std::min(mouse.y + alDragOff.y, screenHeight * 0.9f));
            ArrayListModule::posNX = newAnchor / screenWidth;
            ArrayListModule::posNY = (newTop - 5.0f) / screenHeight;
        }

        ImDrawList* dl = GetBackgroundDrawList();
        const ImU32 editCol = (alDragging || resizing_)
            ? IM_COL32(255, 165, 0, 220)
            : IM_COL32(100, 180, 255, 180);
        dl->AddRect(editMin, editMax, editCol, ROUNDING + 2.0f, 0, 1.5f);

        const ImU32 handleCol = resizing_ ? IM_COL32(255, 165, 0, 255) : IM_COL32(100, 180, 255, 220);
        if (isRight) {

            dl->AddTriangleFilled(
                ImVec2(editMin.x, editMax.y),
                ImVec2(editMin.x + HANDLE_SZ, editMax.y),
                ImVec2(editMin.x, editMax.y - HANDLE_SZ),
                handleCol);
        } else {

            dl->AddTriangleFilled(
                editMax,
                ImVec2(editMax.x - HANDLE_SZ, editMax.y),
                ImVec2(editMax.x, editMax.y - HANDLE_SZ),
                handleCol);
        }
    }

    for (auto& [mod, data] : activeModules) {
        mod = nullptr;
        data.name = nullptr;
        data.flags = nullptr;
    }
    activeModules.clear();
    activeModules.shrink_to_fit();

    secureBufferClear(sharedFlagsBuffer, sizeof(sharedFlagsBuffer));
    clearAllFormatBuffers();
}
