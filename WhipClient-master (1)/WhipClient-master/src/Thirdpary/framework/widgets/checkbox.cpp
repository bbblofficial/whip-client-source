#include "../headers/includes.h"
#include "util/ClientStrings.h"

bool c_widgets::checkbox(const char* name, bool* callback, ImVec4* color, bool conditional)
{
    struct checkbox_state
    {
        float pos, circle, alpha;
        ImVec4 cirlce_color, text_color;
    };

    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems)
    {
        return false;
    }
    ImGuiID id = window->GetID(name);
    checkbox_state* state = gui->anim_container<checkbox_state>(id);

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(gui->content_avail().x, SCALE(elements->checkbox.size));
    ImRect total(pos, pos + size);
    ImRect rect(total.Min + SCALE(elements->padding), total.Max - SCALE(elements->padding));
    ImRect button(ImVec2(rect.Max.x - SCALE(elements->checkbox.button.x), rect.GetCenter().y - SCALE(elements->checkbox.button.y) / 2), ImVec2(rect.Max.x, rect.GetCenter().y + SCALE(elements->checkbox.button.y) / 2));
    ImRect color_rect(button.GetTL() - SCALE(elements->padding.x * 2, 0), button.GetBL() - SCALE(elements->padding.x, 0));
    ImRect settings_rect = (color == nullptr ? ImRect(button.GetTL() - SCALE(elements->padding.x * 2 + 1, 0), button.GetBL() - SCALE(elements->padding.x, 0)) : ImRect(color_rect.GetTL() - SCALE(elements->padding.x * 2 + 1, 0), color_rect.GetBL() - SCALE(elements->padding.x, 0)));

    gui->item_size(total);
    gui->item_add(total, id);
    GetCurrentContext()->LastItemData.GearPos = settings_rect.Min;

    bool pressed = gui->button_behavior(total, id, nullptr, nullptr);

    if (pressed && !color_rect.Contains(GetMousePos()) && !settings_rect.Contains(GetMousePos()))
    {
        *callback = !*callback;
    }

    // For setting (default), always use white text. For conditionals, use active/inactive colors
    if (conditional) {
        gui->easing(state->text_color, *callback ? clr->white.Value : clr->text_inactive.Value, 24.f, smooth_easing);
    } else {
        gui->easing(state->text_color, clr->white.Value, 24.f, smooth_easing);
    }

    gui->easing(state->cirlce_color, *callback ? clr->accent.Value : clr->text_inactive.Value, 24.f, smooth_easing);
    gui->easing(state->alpha, *callback ? 1.f : 0.f, 5.f, smooth_easing);
    gui->easing(state->circle, *callback ? elements->checkbox.cirlce : elements->checkbox.cirlce - 1, 24.f, smooth_easing);
    gui->easing(state->pos, *callback ? SCALE(elements->checkbox.button.x - state->circle - 2) : SCALE(state->circle + 4), 24.f, smooth_easing);

    // Name formatting is now handled by SettingsHandler
    draw->text_clipped(window->DrawList, font->get(my_font, 12), total.Min + SCALE(elements->padding.x, 0), total.Max, draw->get_clr(state->text_color), name, 0, 0, {0, 0.5});
    draw->rect_filled(window->DrawList, button.Min, button.Max, draw->get_clr(clr->accent, 0.2f * state->alpha), SCALE(999));
    draw->rect_filled(window->DrawList, button.Min, button.Max, draw->get_clr(clr->layout, 1.f - state->alpha), SCALE(999));
    draw->circle_filled(window->DrawList, ImVec2(button.Min.x, button.GetCenter().y) + ImVec2(state->pos, 0), SCALE(state->circle), draw->get_clr(state->cirlce_color));

    if (color != nullptr)
    {
        draw->circle_filled(window->DrawList, color_rect.GetCenter(), SCALE(5), draw->get_clr(*color), SCALE(64));

        char colorpicker_id[256];
        snprintf(colorpicker_id, sizeof(colorpicker_id), "%s##colorpicker", name);

        if (color_rect.Contains(GetMousePos()) && gui->mouse_clicked(0))
        {
            widgets->open_popup(colorpicker_id);
        }

        if (widgets->popup(colorpicker_id, color_rect.Min, SCALE(150, 0), SCALE(elements->child.rounding)))
        {
            widgets->colorpicker(name, color);
            widgets->end_popup();
        }
    }

    if (conditional)
    {
        draw->text_clipped(window->DrawList, font->get(icon_font, 11), settings_rect.Min, settings_rect.Max, draw->get_clr(clr->text_inactive), Strings::iconGear(), 0, 0, {0.5, 0.5});
        if (settings_rect.Contains(GetMousePos()) && gui->mouse_clicked(0))
        {
            widgets->open_popup(name);
        }
    }

    if (gui->content_avail().y + gui->get_window()->Scroll.y > 0)
    {
        draw->line(window->DrawList, total.GetBL(), total.GetBR(), draw->get_clr(clr->selection));
    }

    return pressed;
}