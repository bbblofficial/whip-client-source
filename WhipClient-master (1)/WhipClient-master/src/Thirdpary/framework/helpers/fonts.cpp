#include "imgui_freetype.h"
#include "imgui_impl_opengl2.h"
#include "imgui_impl_opengl3.h"
#include "../headers/includes.h"

void c_font::update()
{
    if (var->gui.dpi_changed)
    {
        var->gui.dpi = var->gui.stored_dpi / 100.f;

        ImFontConfig cfg;
        cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_Bitmap;
        cfg.FontDataOwnedByAtlas = false;

        ImGuiIO& io = ImGui::GetIO();
        io.Fonts->Clear();

        for (auto& font_t : data)
        {
            font_t.font = io.Fonts->AddFontFromMemoryTTF(
                font_t.data.data(),
                font_t.data.size(),
                SCALE(font_t.size),
                &cfg,
                io.Fonts->GetGlyphRangesCyrillic()
            );
        }

        io.Fonts->Build();
        ImGui_ImplOpenGL2_DestroyFontsTexture();
        ImGui_ImplOpenGL2_CreateFontsTexture();

        var->gui.dpi_changed = false;
    }
}

ImFont* c_font::get(std::vector<unsigned char> font_data, float size)
{
    if (var->gui.dpi_changed) {
        update();
    }

    for (auto& font : data)
    {
        if (font.data == font_data && font.size == size)
        {
            if (font.font != nullptr && font.font->ContainerAtlas != nullptr) {
                if (font.font->ContainerAtlas->TexID != nullptr) {
                    return font.font;
                }
            }
            break;
        }
    }

    bool font_found = false;
    for (auto& font : data)
    {
        if (font.data == font_data && font.size == size)
        {
            font_found = true;
            break;
        }
    }

    if (!font_found && !fonts_preloaded)
    {
        add(font_data, size);
        var->gui.dpi_changed = true;
        update();

        for (auto& font : data)
        {
            if (font.data == font_data && font.size == size)
            {
                if (font.font != nullptr && font.font->ContainerAtlas != nullptr) {
                    return font.font;
                }
            }
        }
    }

    ImGuiIO& io = ImGui::GetIO();
    if (!io.Fonts->Fonts.empty()) {
        ImFont* fallback = io.Fonts->Fonts[0];
        if (fallback != nullptr && fallback->ContainerAtlas != nullptr && fallback->ContainerAtlas->TexID != nullptr) {
            return fallback;
        }
    }

    return nullptr;
}

void c_font::add(std::vector<unsigned char> font_data, float size)
{
    data.push_back({ font_data, size, nullptr });
}

void c_font::preload_all()
{
    if (fonts_preloaded) {
        return;
    }

    // Preload only GUI fonts
    add(my_font, 10);
    add(my_font, 11);
    add(my_font, 12);
    add(my_font, 14);

    add(icon_font, 8);
    add(icon_font, 10);
    add(icon_font, 11);

    add(custom_icon_font, 11);
    add(custom_icon_font, 12);
    add(custom_icon_font, 14);

    var->gui.dpi_changed = true;
    update();

    fonts_preloaded = true;
}