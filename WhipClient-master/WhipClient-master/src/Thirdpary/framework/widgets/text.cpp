#include "../headers/includes.h"

bool c_widgets::text(const char* text, ImFont* font, ImColor col)
{
    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems)
    {
        return false;
    }
    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = gui->text_size(font, text);
    ImRect rect(pos, pos + size);

    gui->item_size(rect);
    gui->item_add(rect, 0);

    draw->text_clipped(window->DrawList, font, rect.Min, rect.Max, draw->get_clr(col), text, 0, 0, {0, 0});

    return true;
}

bool c_widgets::text_line(const char* text, ImFont* font, ImColor col)
{
    struct text_state
    {
        float alpha;
        ImVec4 text_color;
    };

    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems)
    {
        return false;
    }

    ImGuiID id = window->GetID(text);
    text_state* state = gui->anim_container<text_state>(id);

    // Configuration des dimensions et positions (identique au keybind_button)
    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(gui->content_avail().x, SCALE(elements->checkbox.size));
    ImRect total(pos, pos + size);
    ImRect rect(total.Min + SCALE(elements->padding), total.Max - SCALE(elements->padding));

    // Configuration des interactions
    gui->item_size(total);
    gui->item_add(total, id);
    bool hovered, held;
    bool pressed = gui->button_behavior(total, id, &hovered, &held);

    // Animation
    gui->easing(state->text_color, hovered ? col.Value : col.Value, 24.f, smooth_easing);
    gui->easing(state->alpha, hovered ? 0.1f : 0.0f, 8.f, smooth_easing);

    // Rendu du fond avec hover
    draw->rect_filled(window->DrawList, total.Min, total.Max, draw->get_clr(clr->layout, state->alpha), SCALE(elements->child.rounding));

    // Rendu du texte avec seulement le padding X
    draw->text_clipped(window->DrawList, font,
        total.Min + ImVec2(SCALE(elements->padding.x), 0),
        total.Max,
        draw->get_clr(state->text_color),
        text, 0, 0, { 0, 0.5 });

    // S�parateur en bas
    if (gui->content_avail().y + gui->get_window()->Scroll.y > 0)
    {
        draw->line(window->DrawList, total.GetBL(), total.GetBR(), draw->get_clr(clr->selection));
    }

    return pressed;
}