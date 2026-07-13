#include "../headers/includes.h"
#include <Windows.h>

struct colorpicker_state
{
    bool init = false, pipette_active = false;
    int color_type = 0;
    ImVec2 circle, pipette_pos;
    float radius{ 3 }, h, a, pippete_timer = 0.f;
    float hsv[3];
    ImVec4 gear;
};

bool c_widgets::colorpicker(const char* name, ImVec4* color) {

    ImGuiWindow* window = gui->get_window();

    char picker_state_id[256];
    snprintf(picker_state_id, sizeof(picker_state_id), "%s##picker_state", name);
    ImGuiID id = window->GetID(picker_state_id);
    colorpicker_state* state = gui->anim_container<colorpicker_state>(id);

    if (!state->init)
    {
        ColorConvertRGBtoHSV(color->x, color->y, color->z, state->hsv[0], state->hsv[1], state->hsv[2]);
        state->init = true;
    }

    gui->begin_content("colorpicker", ImVec2(gui->content_avail().x, 0), SCALE(elements->padding), SCALE(elements->padding), window_flags_no_scrollbar | window_flags_no_scroll_with_mouse, child_flags_always_auto_resize | child_flags_auto_resize_y);

    ImVec2 pos;
    ImVec2 mouse_pos = GetMousePos();
    ImVec2 size(gui->content_avail().x, SCALE(elements->colorpicker.sv_height));

    {
        gui->invisible_button("sv", size);
        pos = GetItemRectMin();

        if (gui->is_item_active())
        {
            state->hsv[1] = ImSaturate((mouse_pos.x - pos.x) / size.x);
            state->hsv[2] = 1.0f - ImSaturate((mouse_pos.y - pos.y) / size.y);
        }

        gui->easing(state->radius, gui->is_item_active() ? SCALE(elements->colorpicker.circle_radius + 1) : SCALE(elements->colorpicker.circle_radius), 10.f, smooth_easing);

        draw->rect_filled_multi_color(window->DrawList, GetItemRectMin(), GetItemRectMax() - SCALE(0, 1), draw->get_clr(clr->white), draw->get_clr(ImColor::HSV(state->hsv[0], 1, 1, 1)), draw->get_clr(ImColor::HSV(state->hsv[0], 1, 1, 1)), draw->get_clr(clr->white), SCALE(elements->colorpicker.rounding));
        draw->rect_filled_multi_color(window->DrawList, GetItemRectMin(), GetItemRectMax(), 0, 0, draw->get_clr(clr->black), draw->get_clr(clr->black), SCALE(elements->colorpicker.rounding - 1));
    }

    const ImColor col_hues[7] = { ImColor(255, 0, 0), ImColor(255, 255, 0), ImColor(0, 255, 0), ImColor(0, 255, 255), ImColor(0, 0, 255), ImColor(255, 0, 255), ImColor(255, 0, 0) };

    {
        gui->invisible_button("hue", ImVec2(gui->content_avail().x, SCALE(elements->slider.line_height)));

        ImRect line(GetItemRectMin(), GetItemRectMax());

        if (gui->is_item_active())
        {
            state->hsv[0] = ImSaturate((mouse_pos.x - line.Min.x) / line.GetWidth());
        }

        gui->easing(state->h, state->hsv[0], 24.f, smooth_easing);

        for (int i = 0; i < 6; ++i) {
            float rounding = (i == 0) || (i == 5) ? SCALE(100) : 0;
            draw_flags flags = (i == 0) ? draw_flags_round_corners_left : (i == 5) ? draw_flags_round_corners_right : 0;
            draw->rect_filled_multi_color(window->DrawList, ImVec2(roundf(line.Min.x + i * (line.GetWidth() / 6)), line.Min.y), ImVec2(roundf(line.Min.x + (i + 1) * (line.GetWidth() / 6)), line.Max.y), draw->get_clr(col_hues[i]), draw->get_clr(col_hues[i + 1]), draw->get_clr(col_hues[i + 1]), draw->get_clr(col_hues[i]), rounding, flags);
        }

        float x = line.Min.x + line.GetWidth() * state->h;

        x = ImClamp(x, line.Min.x + SCALE(elements->slider.grab.x) / 2, line.Max.x - SCALE(elements->slider.grab.x) / 2);

        ImRect grab(ImVec2(x - SCALE(elements->slider.grab.x) / 2, line.GetCenter().y - SCALE(elements->slider.grab.y) / 2), ImVec2(x + SCALE(elements->slider.grab.x) / 2, line.GetCenter().y + SCALE(elements->slider.grab.y) / 2));

        draw->circle_filled(window->DrawList, grab.GetCenter(), grab.GetHeight() / 2, draw->get_clr(clr->white));
    }

    {
        gui->invisible_button("alpha", ImVec2(gui->content_avail().x, SCALE(elements->slider.line_height)));

        ImRect line(GetItemRectMin(), GetItemRectMax());

        if (gui->is_item_active())
        {
            color->w = ImSaturate((mouse_pos.x - line.Min.x) / line.GetWidth());
        }

        gui->easing(state->a, color->w, 24.f, smooth_easing);

        draw->rect_filled_multi_color(window->DrawList, line.Min, line.Max, draw->get_clr(clr->white), draw->get_clr(ImColor(color->x, color->y, color->z), 1.f), draw->get_clr(ImColor(color->x, color->y, color->z), 1.f), draw->get_clr(clr->white), SCALE(100));

        float x = line.Min.x + line.GetWidth() * state->a;

        x = ImClamp(x, line.Min.x + SCALE(elements->slider.grab.x) / 2, line.Max.x - SCALE(elements->slider.grab.x) / 2);

        ImRect grab(ImVec2(x - SCALE(elements->slider.grab.x) / 2, line.GetCenter().y - SCALE(elements->slider.grab.y) / 2), ImVec2(x + SCALE(elements->slider.grab.x) / 2, line.GetCenter().y + SCALE(elements->slider.grab.y) / 2));

        draw->circle_filled(window->DrawList, grab.GetCenter(), grab.GetHeight() / 2, draw->get_clr(clr->white));
    }

    ImVec2 sv_cursor_pos;
    sv_cursor_pos.x = ImClamp(IM_ROUND(pos.x + ImSaturate(state->hsv[1]) * size.x), pos.x + state->radius + SCALE(elements->colorpicker.circle_thikness / 2), pos.x + size.x - state->radius - SCALE(elements->colorpicker.circle_thikness / 2));
    sv_cursor_pos.y = ImClamp(IM_ROUND(pos.y + ImSaturate(1 - state->hsv[2]) * size.y), pos.y + state->radius + SCALE(elements->colorpicker.circle_thikness / 2), pos.y + size.y - state->radius - SCALE(elements->colorpicker.circle_thikness / 2));

    gui->easing(state->circle.x, sv_cursor_pos.x - pos.x, 24.f, smooth_easing);
    gui->easing(state->circle.y, sv_cursor_pos.y - pos.y, 24.f, smooth_easing);

    draw->shadow_circle(window->DrawList, state->circle + pos, state->radius, draw->get_clr(clr->black), state->radius * 3, ImVec2(0, 0));
    draw->circle(window->DrawList, state->circle + pos, state->radius, draw->get_clr(clr->white), SCALE(32), SCALE(elements->colorpicker.circle_thikness));

    ColorConvertHSVtoRGB(state->hsv[0], state->hsv[1], state->hsv[2], color->x, color->y, color->z);

    gui->end_content();

    return true;
}

bool c_widgets::color_selector2(const char* name, ImVec4* color)
{
    struct color_state
    {
        float alpha;
        ImVec4 text_color;
    };

    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems)
    {
        return false;
    }

    ImGuiID id = window->GetID(name);
    color_state* state = gui->anim_container<color_state>(id);

    // Configuration des dimensions et positions (identique au checkbox)
    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(gui->content_avail().x, SCALE(elements->checkbox.size));
    ImRect total(pos, pos + size);
    ImRect rect(total.Min + SCALE(elements->padding), total.Max - SCALE(elements->padding));

    // Utiliser la m�me position que le bouton dans checkbox
    ImRect button(
        ImVec2(rect.Max.x - SCALE(elements->checkbox.button.x), rect.GetCenter().y - SCALE(elements->checkbox.button.y) / 2),
        ImVec2(rect.Max.x, rect.GetCenter().y + SCALE(elements->checkbox.button.y) / 2)
    );

    // Le carr� de couleur utilise l'emplacement du bouton
    ImRect color_rect = button;

    // Configuration des interactions
    gui->item_size(total);
    gui->item_add(total, id);
    bool hovered, held;
    bool pressed = gui->button_behavior(total, id, &hovered, &held);

    // Animation
    gui->easing(state->text_color, hovered ? clr->white.Value : clr->white.Value, 24.f, smooth_easing);
    gui->easing(state->alpha, hovered ? 0.1f : 0.0f, 8.f, smooth_easing);

    // Rendu du texte et du fond
    draw->rect_filled(window->DrawList, total.Min, total.Max, draw->get_clr(clr->layout, state->alpha), SCALE(elements->child.rounding));
    draw->text_clipped(window->DrawList, font->get(my_font, 12), total.Min + SCALE(elements->padding.x, 0), total.Max,
        draw->get_clr(state->text_color), name, 0, 0, { 0, 0.5 });

    // Rendu du carr� de couleur aux dimensions du bouton
    ImU32 color_u32 = ImGui::ColorConvertFloat4ToU32(*color);
    draw->rect_filled(window->DrawList, color_rect.Min, color_rect.Max, color_u32, SCALE(3));

    // S�parateur en bas
    if (gui->content_avail().y + gui->get_window()->Scroll.y > 0)
    {
        draw->line(window->DrawList, total.GetBL(), total.GetBR(), draw->get_clr(clr->selection));
    }

    return pressed;
}

bool c_widgets::color_selector(const char* name, ImVec4* color)
{
    struct color_state
    {
        float alpha;
        ImVec4 text_color;
        bool force_open;
        int open_frames;
    };

    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems)
    {
        return false;
    }

    ImGuiID id = window->GetID(name);
    color_state* state = gui->anim_container<color_state>(id);

    // Configuration des dimensions et positions (identique au checkbox)
    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(gui->content_avail().x, SCALE(elements->checkbox.size));
    ImRect total(pos, pos + size);
    ImRect rect(total.Min + SCALE(elements->padding), total.Max - SCALE(elements->padding));

    // Utiliser la m�me position que le bouton dans checkbox
    ImRect button(
        ImVec2(rect.Max.x - SCALE(elements->checkbox.button.x), rect.GetCenter().y - SCALE(elements->checkbox.button.y) / 2),
        ImVec2(rect.Max.x, rect.GetCenter().y + SCALE(elements->checkbox.button.y) / 2)
    );

    // Le carr� de couleur utilise l'emplacement du bouton, avec une taille ajust�e
    ImRect color_rect = button;

    // Configuration des interactions
    gui->item_size(total);
    gui->item_add(total, id);

    bool hovered, held;
    bool pressed = gui->button_behavior(total, id, &hovered, &held);

    // Animation
    gui->easing(state->text_color, hovered ? clr->white.Value : clr->white.Value, 24.f, smooth_easing);
    gui->easing(state->alpha, hovered ? 0.1f : 0.0f, 8.f, smooth_easing);

    // Rendu du texte et du fond
    draw->rect_filled(window->DrawList, total.Min, total.Max, draw->get_clr(clr->layout, state->alpha), SCALE(elements->child.rounding));
    draw->text_clipped(window->DrawList, font->get(my_font, 12), total.Min + SCALE(elements->padding.x, 0), total.Max,
        draw->get_clr(state->text_color), name, 0, 0, { 0, 0.5 });

    // Rendu du carr� de couleur aux dimensions du bouton
    const float rounding = SCALE(3);
    draw->rect_filled(window->DrawList, color_rect.Min, color_rect.Max,
        draw->get_clr(*color), SCALE(999));

    // S�parateur en bas
    if (gui->content_avail().y + gui->get_window()->Scroll.y > 0)
    {
        draw->line(window->DrawList, total.GetBL(), total.GetBR(), draw->get_clr(clr->selection));
    }

    // Nom unique pour la popup
    char popup_name[256];
    snprintf(popup_name, sizeof(popup_name), "%s##colorpicker", name);

    // Si le carr� de couleur est cliqu�
    if (color_rect.Contains(GetMousePos()) && gui->mouse_clicked(0))
    {
        // Fermer toutes les autres popups ouvertes
        for (auto& popup : widgets->popup_storage)
        {
            if (popup.name != popup_name && popup.open)
            {
                widgets->close_popup(popup.name);
            }
        }

        // Ouvrir cette popup et d�finir le drapeau pour forcer l'ouverture
        widgets->open_popup(popup_name);
        state->force_open = true;
        state->open_frames = 5; // Forcer l'ouverture pendant 5 frames
    }

    // Si nous devons forcer l'ouverture de la popup
    if (state->force_open && state->open_frames > 0)
    {
        // S'assurer que la popup reste ouverte
        widgets->open_popup(popup_name);
        state->open_frames--;

        // Si le compteur atteint z�ro, arr�ter de forcer l'ouverture
        if (state->open_frames <= 0)
        {
            state->force_open = false;
        }
    }

    // Afficher la popup si elle est ouverte
    bool popup_displayed = widgets->popup(popup_name, color_rect.Min, SCALE(150, 0), SCALE(elements->child.rounding));

    if (popup_displayed)
    {
        widgets->colorpicker(name, color);
        widgets->end_popup();
    }
    else if (state->force_open)
    {
        // Si la popup devrait �tre affich�e mais ne l'est pas, essayer de la rouvrir
        widgets->open_popup(popup_name);
    }

    return pressed;
}