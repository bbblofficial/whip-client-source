#include "../../../includes/hud/sub/NotificationHUDElement.h"
#include "handler/ModuleHandler.h"
#include "gui/includes.h"
#include "imgui_freetype.h"
#include "imgui_impl_opengl2.h"
#include "imgui_impl_opengl3.h"
#include "gui/Gui.h"
#include <algorithm>

NotificationHUDElement::NotificationHUDElement() {
    config = static_cast<NotificationModule*>(
        ModuleHandler::getInstance().getModule<ModuleType::NOTIFICATION>()
    );
}

void NotificationHUDElement::initializeFonts() {
    if (fontsInitialized) return;

    ImGuiIO& io = GetIO();
    ImFontConfig cfg;
    cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_Bitmap;
    cfg.FontDataOwnedByAtlas = false;

    const float baseSize = BASE_FONT_SIZE;
    const float scaleMin = 0.5f;
    const float scaleMax = 2.0f;
    const float scaleStep = 0.1f;

    for (float scale = scaleMin; scale <= scaleMax; scale += scaleStep) {
        float size = baseSize * scale;

        ImFont* newFont = io.Fonts->AddFontFromMemoryTTF(
            const_cast<void*>(static_cast<const void*>(Poppins_SemiBold_compressed_data.data())),
            static_cast<int>(Poppins_SemiBold_compressed_data.size()),
            size,
            &cfg,
            io.Fonts->GetGlyphRangesCyrillic()
        );

        if (newFont != nullptr) {
            cachedFonts[size] = newFont;
        }
    }

    io.Fonts->Build();
    ImGui_ImplOpenGL2_DestroyFontsTexture();
    ImGui_ImplOpenGL2_CreateFontsTexture();

    fontsInitialized = !cachedFonts.empty();
}

ImFont* NotificationHUDElement::getOrCreateFont(float size) {
    if (!fontsInitialized) {
        initializeFonts();
    }

    ImFont* closestFont = nullptr;
    float minDiff = FLT_MAX;

    for (const auto& [cachedSize, cachedFont] : cachedFonts) {
        if (cachedFont != nullptr && cachedFont->ContainerAtlas != nullptr &&
            cachedFont->ContainerAtlas->TexID != nullptr) {
            float diff = std::abs(cachedSize - size);
            if (diff < minDiff) {
                minDiff = diff;
                closestFont = cachedFont;

                if (diff < 0.5f) {
                    return closestFont;
                }
            }
        }
    }

    if (closestFont != nullptr) {
        return closestFont;
    }

    ImGuiIO& io = GetIO();
    if (!io.Fonts->Fonts.empty()) {
        return io.Fonts->Fonts[0];
    }

    return nullptr;
}

void NotificationHUDElement::onRender() {
    if (!config || !config->isEnabled()) return;

    const ImGuiIO& io = GetIO();
    ImDrawList* drawList = GetBackgroundDrawList();

    const float screenWidth = io.DisplaySize.x;
    const float screenHeight = io.DisplaySize.y;

    const auto& notifications = config->getNotifications();
    const bool hasEditGhost = Gui::getInstance().isOpen();

    if (notifications.empty() && !hasEditGhost) return;

    ImFont* notificationFont = getOrCreateFont(BASE_FONT_SIZE);
    if (notificationFont == nullptr) return;

    gui->push_font(notificationFont);

    ImFont* scaledFont = getOrCreateFont(BASE_FONT_SIZE * NotificationModule::scale);

    auto drawOneNotification = [&](float finalX, float finalY, float width, float height,
                                    float opacity, ImColor barColor, const char* text, ImVec2 textSize) {

        draw->rect_filled(drawList,
            ImVec2(finalX, finalY), ImVec2(finalX + width, finalY + height),
            draw->get_clr(ImVec4(35.0f/255.0f, 34.0f/255.0f, 34.0f/255.0f, (180.0f/255.0f) * opacity)),
            ROUNDING * NotificationModule::scale, draw_flags_round_corners_all);

        const float barWidth = 2.5f * NotificationModule::scale;
        ImColor bc = barColor;
        bc.Value.w *= opacity;

        if (static_cast<NotificationModule::Position>(NotificationModule::position) == NotificationModule::Position::TOP_RIGHT ||
            static_cast<NotificationModule::Position>(NotificationModule::position) == NotificationModule::Position::BOTTOM_RIGHT) {
            draw->rect_filled(drawList,
                ImVec2(finalX + width - barWidth, finalY), ImVec2(finalX + width, finalY + height),
                draw->get_clr(bc), ROUNDING * NotificationModule::scale, draw_flags_round_corners_all);
        } else {
            draw->rect_filled(drawList,
                ImVec2(finalX, finalY), ImVec2(finalX + barWidth, finalY + height),
                draw->get_clr(bc), ROUNDING * NotificationModule::scale, draw_flags_round_corners_all);
        }

        const float textX = finalX + (NOTIFICATION_PADDING * NotificationModule::scale) +
            (static_cast<NotificationModule::Position>(NotificationModule::position) == NotificationModule::Position::TOP_RIGHT ||
             static_cast<NotificationModule::Position>(NotificationModule::position) == NotificationModule::Position::BOTTOM_RIGHT ? 0.0f : barWidth);
        const float textY = finalY + (height - textSize.y) * 0.5f;

        if (scaledFont) {
            draw->text(drawList, scaledFont, BASE_FONT_SIZE * NotificationModule::scale,
                ImVec2(textX, textY),
                draw->get_clr(ImVec4(1.0f, 1.0f, 1.0f, opacity)),
                text);
        }
    };

    if (hasEditGhost) {
        constexpr const char* ghostText = "Notification";
        ImVec2 ghostTextSize = notificationFont->CalcTextSizeA(BASE_FONT_SIZE, FLT_MAX, 0.0f, ghostText);
        ghostTextSize.x *= NotificationModule::scale;
        ghostTextSize.y *= NotificationModule::scale;

        const float ghostW = ghostTextSize.x + (NOTIFICATION_PADDING * 2 * NotificationModule::scale);
        const float ghostH = NOTIFICATION_HEIGHT * NotificationModule::scale;

        static bool   ghostDragging = false;
        static ImVec2 ghostDragOff;

        const ImVec2 mouse   = ImGui::GetMousePos();
        const bool   down    = ImGui::IsMouseDown(0);
        const bool   clicked = ImGui::IsMouseClicked(0);

        ImVec2 ghostPos = config->calculateNotificationPosition(ghostW, ghostH, screenWidth, screenHeight, 0);
        float  gx = ghostPos.x;
        float  gy = ghostPos.y;

        constexpr float HANDLE_SZ = 12.0f;
        const ImVec2 resizeCorner(gx + ghostW, gy + ghostH);
        const ImRect resizeRect(
            ImVec2(resizeCorner.x - HANDLE_SZ, resizeCorner.y - HANDLE_SZ),
            resizeCorner);

        if (clicked) {
            if (resizeRect.Contains(mouse)) {
                resizing_ = true;
                resizeBaseScale_ = NotificationModule::scale;
                resizeBaseMouseX_ = mouse.x;
                ghostDragging = false;
            } else {
                const bool inRect = mouse.x >= gx && mouse.x <= gx + ghostW
                                 && mouse.y >= gy && mouse.y <= gy + ghostH;
                if (inRect) {
                    ghostDragging = true;
                    ghostDragOff  = ImVec2(gx - mouse.x, gy - mouse.y);
                    resizing_ = false;
                } else {
                    ghostDragging = false;
                    resizing_ = false;
                }
            }
        }

        if (resizing_) {
            if (down) {
                float delta = (mouse.x - resizeBaseMouseX_) * 0.01f;
                NotificationModule::scale = std::clamp(resizeBaseScale_ + delta, 0.5f, 2.0f);
            } else {
                resizing_ = false;
            }
        }

        if (ghostDragging) {
            if (down) {

                float nx = mouse.x + ghostDragOff.x;
                float ny = mouse.y + ghostDragOff.y;
                nx = std::max(0.0f, std::min(nx, screenWidth  - ghostW));
                ny = std::max(0.0f, std::min(ny, screenHeight - ghostH));

                const float cx = nx + ghostW * 0.5f;
                const float cy = ny + ghostH * 0.5f;

                if (cx < screenWidth * 0.5f && cy < screenHeight * 0.5f) {
                    NotificationModule::position = static_cast<int>(NotificationModule::Position::TOP_LEFT);
                    NotificationModule::marginX  = nx;
                    NotificationModule::marginY  = ny;
                } else if (cx >= screenWidth * 0.5f && cy < screenHeight * 0.5f) {
                    NotificationModule::position = static_cast<int>(NotificationModule::Position::TOP_RIGHT);
                    NotificationModule::marginX  = screenWidth - (nx + ghostW);
                    NotificationModule::marginY  = ny;
                } else if (cx < screenWidth * 0.5f) {
                    NotificationModule::position = static_cast<int>(NotificationModule::Position::BOTTOM_LEFT);
                    NotificationModule::marginX  = nx;
                    NotificationModule::marginY  = screenHeight - (ny + ghostH);
                } else {
                    NotificationModule::position = static_cast<int>(NotificationModule::Position::BOTTOM_RIGHT);
                    NotificationModule::marginX  = screenWidth - (nx + ghostW);
                    NotificationModule::marginY  = screenHeight - (ny + ghostH);
                }

                ghostPos = config->calculateNotificationPosition(ghostW, ghostH, screenWidth, screenHeight, 0);
                gx = ghostPos.x;
                gy = ghostPos.y;
            } else {
                ghostDragging = false;
            }
        }

        constexpr float ghostOpacity = 0.6f;
        drawOneNotification(gx, gy, ghostW, ghostH, ghostOpacity, NotificationModule::infoColor, ghostText, ghostTextSize);

        const ImU32 borderCol = (ghostDragging || resizing_)
            ? IM_COL32(255, 165, 0, 220)
            : IM_COL32(100, 180, 255, 180);
        drawList->AddRect(
            ImVec2(gx - 2.0f, gy - 2.0f),
            ImVec2(gx + ghostW + 2.0f, gy + ghostH + 2.0f),
            borderCol,
            ROUNDING * NotificationModule::scale + 2.0f, 0, 1.5f);

        const ImU32 handleCol = resizing_ ? IM_COL32(255, 165, 0, 255) : IM_COL32(100, 180, 255, 220);
        drawList->AddTriangleFilled(
            ImVec2(gx + ghostW + 2.0f, gy + ghostH + 2.0f),
            ImVec2(gx + ghostW + 2.0f - HANDLE_SZ, gy + ghostH + 2.0f),
            ImVec2(gx + ghostW + 2.0f, gy + ghostH + 2.0f - HANDLE_SZ),
            handleCol);
    }

    int index = 0;
    for (const auto& notification : notifications) {
        const char* messageText = notification.getMessage();
        if (!messageText || messageText[0] == '\0') {
            continue;
        }

        ImVec2 textSize = notificationFont->CalcTextSizeA(BASE_FONT_SIZE, FLT_MAX, 0.0f, messageText);
        textSize.x *= NotificationModule::scale;
        textSize.y *= NotificationModule::scale;

        const float width  = textSize.x + (NOTIFICATION_PADDING * 2 * NotificationModule::scale);
        const float height = NOTIFICATION_HEIGHT * NotificationModule::scale;

        const ImVec2 basePos = config->calculateNotificationPosition(width, height, screenWidth, screenHeight, index);
        const float xOffset  = config->calculateAnimationOffset(notification);

        drawOneNotification(basePos.x + xOffset, basePos.y, width, height,
            notification.opacity, notification.color, messageText, textSize);

        index++;
    }

    gui->pop_font();
}
