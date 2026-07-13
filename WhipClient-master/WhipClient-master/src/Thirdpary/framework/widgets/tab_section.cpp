#include "../headers/includes.h"
#include "util/ClientStrings.h"

struct tab_section_state_t {
    bool open, init;
    float height, rad, alpha, width;
    ImVec4 color, header;
};

struct section_button_state_t {
    float height, alpha, pos;
    ImVec4 color;
};

bool c_widgets::selectable(const char* name, bool selected) {
    ImGuiWindow *window = gui->get_window();
    if (window->SkipItems)
        return false;

    char unique_name_buffer[256];
    snprintf(unique_name_buffer, sizeof(unique_name_buffer), "%s##selectable_%p", name, this);
    ImGuiID id = window->GetID(unique_name_buffer);

    section_button_state_t *state = gui->anim_container<section_button_state_t>(id);

    gui->easing(state->alpha, selected ? 1.f : 0.f, 15.f, smooth_easing);
    state->height = 15.f + 10.f * state->alpha;
    gui->easing(state->color, selected ? clr->white.Value : clr->text_inactive.Value, 15.f, smooth_easing);
    gui->easing(state->pos, selected ? elements->padding.x * 2.5f : 0.f, 15.f, smooth_easing);

    float actual_height = std::max(SCALE(state->height), SCALE(20.0f));
    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(gui->content_avail().x, actual_height);
    ImRect rect(pos, pos + size);

    gui->item_size(rect);
    gui->item_add(rect, id);

        ImVec2 mouse_pos = ImGui::GetMousePos();
    bool pressed = !widgets->modal_open && rect.Contains(mouse_pos) && ImGui::IsMouseClicked(ImGuiMouseButton_Left);

    // Rendu
    draw->push_clip_rect(window->DrawList, rect.Min, rect.Max, true);
    draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->selection, state->alpha),
                      SCALE(elements->tab_section.rounding));
    draw->text_clipped(window->DrawList, font->get(icon_font, 10),
                       rect.Min + SCALE(state->pos - elements->padding.x * 1.5f, 0), rect.Max,
                       draw->get_clr(clr->accent, state->alpha), Strings::iconDown(), 0, 0, {0, 0.5});
    draw->text_clipped(window->DrawList, font->get(my_font, 12), rect.Min + SCALE(state->pos, 0), rect.Max,
                       draw->get_clr(state->color), name, 0, 0, {0, 0.5});
    draw->pop_clip_rect(window->DrawList);

    // const char* points to TRACKED_STATIC_STRING - no manual cleanup needed

    return pressed;
}

bool c_widgets::tab_section(const char* name, const std::vector<const char*>& variants, std::vector<int> tabs) {
    // const char* variants point to TRACKED_STATIC_STRING - no cleanup needed
    ImGuiWindow *window = gui->get_window();
    if (window->SkipItems) {
        return false;
    }
    ImGuiID id = window->GetID(name);
    tab_section_state_t *state = gui->anim_container<tab_section_state_t>(id);
    if (!state->init) {
        state->width = gui->content_avail().x;
        state->init = true;
    }
    gui->easing(state->alpha, state->open ? 1.f : 0.f, 7.f, smooth_easing);
    gui->easing(state->width, gui->content_avail().x, 24.f, smooth_easing);
    gui->easing(state->rad, state->open ? 360.f : 180.f, 24.f, smooth_easing);
    gui->easing(state->color, state->open ? clr->white.Value : clr->text_inactive.Value, 24.f, smooth_easing);
    gui->easing(state->header, state->open ? clr->selection.Value : clr->child.Value, 24.f, smooth_easing);
    char tab_section_buffer[32];
    snprintf(tab_section_buffer, sizeof(tab_section_buffer), "##ts_%u", id);
    gui->begin_content(tab_section_buffer,
                       ImVec2(state->width, SCALE(elements->tab_section.header) + state->height), SCALE(0, 0),
                       SCALE(0, 0),
                       window_flags_no_scroll_with_mouse | window_flags_no_scrollbar | window_flags_no_move); {
        ImDrawList *drawlist = gui->get_window()->DrawList;
        ImRect rect;
        char ts_header_id[32];
        snprintf(ts_header_id, sizeof(ts_header_id), "##h_%u", id);
        gui->begin_content(ts_header_id, ImVec2(gui->content_avail().x, SCALE(elements->tab_section.header)), SCALE(0, 0),
                           SCALE(0, 0)); {
            rect = gui->get_window()->Rect();
            ImRect inner = ImRect(rect.Min + SCALE(elements->padding.x, 0), rect.Max - SCALE(elements->padding.x, 0));
            ImRect arrow = ImRect(inner.GetTR() - SCALE(8, 0), inner.GetBR());
            draw->rect_filled(drawlist, rect.Min, rect.Max, draw->get_clr(state->header),
                              SCALE(elements->tab_section.rounding), draw_flags_round_corners_top);
            draw->text_clipped(drawlist, font->get(my_font, 12), inner.Min, inner.Max, draw->get_clr(clr->accent),
                               name, 0, 0, {0, 0.5});

            draw->rotate_start(drawlist);
            draw->text_clipped(drawlist, font->get(icon_font, 8), arrow.Min, arrow.Max, draw->get_clr(state->color),
                               Strings::iconDown(), 0, 0, {0.5, 0.5});
            draw->rotate_end(drawlist, state->rad, arrow.GetCenter());

            if (!widgets->modal_open && rect.Contains(GetMousePos()) && gui->is_window_hovered(0) && gui->mouse_clicked(0)) {
                state->open = !state->open;
            }
        }
        gui->end_content();
        gui->push_var(style_var_alpha, state->alpha);
        char ts_buttons_id[32];
        snprintf(ts_buttons_id, sizeof(ts_buttons_id), "##b_%u", id);
        gui->begin_content(ts_buttons_id, ImVec2(gui->content_avail().x, 0), SCALE(elements->padding),
                           SCALE(elements->padding), window_flags_no_scroll_with_mouse | window_flags_no_scrollbar,
                           child_flags_always_auto_resize | child_flags_auto_resize_y); {
            rect = gui->get_window()->Rect();
            draw->rect_filled(drawlist, rect.Min, rect.Max, draw->get_clr(clr->child),
                              SCALE(elements->tab_section.rounding), draw_flags_round_corners_bottom);
            draw->line(drawlist, rect.GetTL(), rect.GetTR(), draw->get_clr(clr->selection));

            if (state->open) {
                for (int i = 0; i < variants.size(); ++i) {
                    if (widgets->selectable(variants[i], var->gui.stored == tabs[i])) {
                        var->gui.stored = tabs[i];
                    }
                }
            }

            state->height = gui->get_window()->Size.y * state->alpha;
        }
        gui->end_content();
        gui->pop_var();
    }
    gui->end_content();
    return true;
}

bool c_widgets::dropdown_section(const char* name, int *callback, const std::vector<const char*>& variants) {

    ImGuiWindow *window = gui->get_window();
    if (window->SkipItems) {
        return false;
    }

    ImGuiID id = window->GetID(name);
    tab_section_state_t *state = gui->anim_container<tab_section_state_t>(id);

    if (!state->init) {
        state->width = gui->content_avail().x - SCALE(20);
        state->init = true;
    }

    static ImVec2 last_window_pos = ImVec2(-1, -1);
    ImVec2 current_pos = window->Pos;
    if (last_window_pos.x != -1 && (abs(current_pos.x - last_window_pos.x) > 1.0f || abs(
                                        current_pos.y - last_window_pos.y) > 1.0f)) {
        if (state->open) {
            state->open = false;
            state->alpha = 0.0f;
        }
    }
    last_window_pos = current_pos;

    gui->easing(state->alpha, state->open ? 1.f : 0.f, 7.f, smooth_easing);
    gui->easing(state->width, gui->content_avail().x - SCALE(20), 24.f, smooth_easing);
    gui->easing(state->rad, state->open ? 360.f : 180.f, 24.f, smooth_easing);
    gui->easing(state->color, state->open ? clr->white.Value : clr->text_inactive.Value, 24.f, smooth_easing);

    bool value_changed = false;

    gui->dummy(ImVec2(SCALE(10), 0));
    gui->sameline();

    char dropdown_section_id[32];
    snprintf(dropdown_section_id, sizeof(dropdown_section_id), "##ds_%u", id);
    gui->begin_content(dropdown_section_id,
                       ImVec2(state->width, SCALE(elements->tab_section.header) + state->height), SCALE(0, 0),
                       SCALE(0, 0),
                       window_flags_no_scroll_with_mouse | window_flags_no_scrollbar | window_flags_no_move); {
        ImDrawList *drawlist = gui->get_window()->DrawList;
        ImRect rect;

        char header_id[32];
        snprintf(header_id, sizeof(header_id), "##h_%u", id);
        gui->begin_content(header_id, ImVec2(gui->content_avail().x, SCALE(elements->tab_section.header)), SCALE(0, 0),
                           SCALE(0, 0)); {
            rect = gui->get_window()->Rect();
            ImRect inner = ImRect(rect.Min + SCALE(elements->padding.x, 0), rect.Max - SCALE(elements->padding.x, 0));
            ImRect arrow = ImRect(inner.GetTR() - SCALE(8, 0), inner.GetBR());

            draw->rect_filled(drawlist, rect.Min, rect.Max, draw->get_clr(clr->selection),
                              SCALE(elements->tab_section.rounding), draw_flags_round_corners_top);

            char display_text[256];
            if (*callback >= 0 && *callback < variants.size()) {
                snprintf(display_text, sizeof(display_text), "%s: %s", name, variants[*callback]);
            } else {
                snprintf(display_text, sizeof(display_text), "%s", name);
            }

            draw->text_clipped(drawlist, font->get(my_font, 12), inner.Min, inner.Max, draw->get_clr(clr->white),
                               display_text, 0, 0, {0, 0.5});

            draw->rotate_start(drawlist);
            draw->text_clipped(drawlist, font->get(icon_font, 8), arrow.Min, arrow.Max, draw->get_clr(state->color),
                               Strings::iconDown(), 0, 0, {0.5, 0.5});
            draw->rotate_end(drawlist, state->rad, arrow.GetCenter());

            if (rect.Contains(GetMousePos()) && gui->is_window_hovered(0) && gui->mouse_clicked(0)) {
                state->open = !state->open;
            }
        }
        gui->end_content();

        gui->push_var(style_var_alpha, state->alpha);

        char content_id[32];
        snprintf(content_id, sizeof(content_id), "##c_%u", id);
        gui->begin_content(content_id, ImVec2(gui->content_avail().x, 0), SCALE(elements->padding),
                           SCALE(elements->padding),
                           window_flags_no_scroll_with_mouse | window_flags_no_scrollbar |
                           ImGuiWindowFlags_NoSavedSettings,
                           child_flags_always_auto_resize | child_flags_auto_resize_y); {
            rect = gui->get_window()->Rect();

            // Draw dropdown background
            draw->rect_filled(drawlist, rect.Min, rect.Max, draw->get_clr(clr->child),
                              SCALE(elements->tab_section.rounding), draw_flags_round_corners_bottom);
            draw->line(drawlist, rect.GetTL(), rect.GetTR(), draw->get_clr(clr->selection));

            // Render selectable options - MODIFIER ICI pour commencer � l'index 1 au lieu de 0
            for (int i = 1; i < variants.size(); ++i) // Changer i = 0 en i = 1
            {
                if (widgets->selectable(variants[i], *callback == i)) {
                    *callback = i;
                    value_changed = true;
                    state->open = false; // Close dropdown after selection (corrected from true to false)
                }
            }

            state->height = gui->get_window()->Size.y * state->alpha;
        }

        gui->end_content();
        gui->pop_var();
    }
    gui->end_content();

    return value_changed;
}

bool c_widgets::dropdown_section_ex(const char* name, int *callback, const std::vector<const char*>& variants,
                                    bool auto_close) {

    ImGuiWindow *window = gui->get_window();
    if (window->SkipItems) {
        return false;
    }

    ImGuiID id = window->GetID(name);
    tab_section_state_t *state = gui->anim_container<tab_section_state_t>(id);

    if (!state->init) {
        state->width = gui->content_avail().x;
        state->init = true;
    }

    if (auto_close && state->open && gui->mouse_clicked(0)) {
        ImVec2 mouse_pos = GetMousePos();
        ImRect section_rect = ImRect(window->DC.CursorPos,
                                     window->DC.CursorPos + ImVec2(state->width,
                                                                   SCALE(elements->tab_section.header) + state->
                                                                   height));

        if (!section_rect.Contains(mouse_pos)) {
            state->open = false;
        }
    }

    gui->easing(state->alpha, state->open ? 1.f : 0.f, 7.f, smooth_easing);
    gui->easing(state->width, gui->content_avail().x, 24.f, smooth_easing);
    gui->easing(state->rad, state->open ? 360.f : 180.f, 24.f, smooth_easing);
    gui->easing(state->color, state->open ? clr->white.Value : clr->text_inactive.Value, 24.f, smooth_easing);
    gui->easing(state->header, state->open ? clr->selection.Value : clr->child.Value, 24.f, smooth_easing);

    bool value_changed = false;

    char dropdown_section_ex_id[32];
    snprintf(dropdown_section_ex_id, sizeof(dropdown_section_ex_id), "##dsx_%u", id);

    gui->begin_content(dropdown_section_ex_id,
                       ImVec2(state->width, SCALE(elements->tab_section.header) + state->height), SCALE(0, 0),
                       SCALE(0, 0),
                       window_flags_no_scroll_with_mouse | window_flags_no_scrollbar | window_flags_no_move); {
        ImDrawList *drawlist = gui->get_window()->DrawList;
        ImRect rect;

        char header_id[32];
        snprintf(header_id, sizeof(header_id), "##h_%u", id);
        gui->begin_content(header_id, ImVec2(gui->content_avail().x, SCALE(elements->tab_section.header)), SCALE(0, 0),
                           SCALE(0, 0)); {
            rect = gui->get_window()->Rect();
            ImRect inner = ImRect(rect.Min + SCALE(elements->padding.x, 0), rect.Max - SCALE(elements->padding.x, 0));
            ImRect arrow = ImRect(inner.GetTR() - SCALE(8, 0), inner.GetBR());

            draw->rect_filled(drawlist, rect.Min, rect.Max, draw->get_clr(state->header),
                              SCALE(elements->tab_section.rounding), draw_flags_round_corners_top);

            // Build display text with selected variant
            char display_text[256];
            if (*callback >= 0 && *callback < variants.size()) {
                snprintf(display_text, sizeof(display_text), "%s: %s", name, variants[*callback]);
            } else {
                snprintf(display_text, sizeof(display_text), "%s", name);
            }

            draw->text_clipped(drawlist, font->get(my_font, 12), inner.Min, inner.Max, draw->get_clr(clr->white),
                               display_text, 0, 0, {0, 0.5});

            draw->rotate_start(drawlist);
            draw->text_clipped(drawlist, font->get(icon_font, 8), arrow.Min, arrow.Max, draw->get_clr(state->color),
                               Strings::iconDown(), 0, 0, {0.5, 0.5});
            draw->rotate_end(drawlist, state->rad, arrow.GetCenter());

            if (rect.Contains(GetMousePos()) && gui->is_window_hovered(0) && gui->mouse_clicked(0)) {
                state->open = !state->open;
            }
        }
        gui->end_content();

        gui->push_var(style_var_alpha, state->alpha);
        char content_id[32];
        snprintf(content_id, sizeof(content_id), "##c_%u", id);
        gui->begin_content(content_id, ImVec2(gui->content_avail().x, 0), SCALE(elements->padding),
                           SCALE(elements->padding), window_flags_no_scroll_with_mouse | window_flags_no_scrollbar,
                           child_flags_always_auto_resize | child_flags_auto_resize_y); {
            rect = gui->get_window()->Rect();

            draw->rect_filled(drawlist, rect.Min, rect.Max, draw->get_clr(clr->child),
                              SCALE(elements->tab_section.rounding), draw_flags_round_corners_bottom);
            draw->line(drawlist, rect.GetTL(), rect.GetTR(), draw->get_clr(clr->selection));

            for (int i = 0; i < variants.size(); ++i) {
                if (widgets->selectable(variants[i], *callback == i)) {
                    *callback = i;
                    value_changed = true;
                    if (auto_close) {
                        state->open = false;
                    }
                }
            }

            state->height = gui->get_window()->Size.y * state->alpha;
        }
        gui->end_content();
        gui->pop_var();
    }
    gui->end_content();

    return value_changed;
}