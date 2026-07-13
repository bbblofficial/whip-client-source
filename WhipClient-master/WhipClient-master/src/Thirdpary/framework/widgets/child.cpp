#include "../headers/includes.h"

void c_widgets::child(const char* name)
{
    // Use automatic buffers (not static - each call gets its own)
    char content_buffer[128];
    char header_buffer[32];
    char widgets_buffer[32];

    // Build the names in automatic buffers
    snprintf(content_buffer, sizeof(content_buffer), "%s##child", name);
    snprintf(header_buffer, sizeof(header_buffer), "header");
    snprintf(widgets_buffer, sizeof(widgets_buffer), "widgets");

    gui->begin_content(content_buffer, ImVec2(elements->child.width, 0), SCALE(0, 0), SCALE(0, 0),
                      window_flags_no_scroll_with_mouse | window_flags_no_scrollbar | window_flags_no_move,
                      child_flags_always_auto_resize | child_flags_auto_resize_y);
    {
        ImDrawList* drawlist = gui->get_window()->DrawList;
        ImRect rect = gui->get_window()->Rect();

        draw->rect_filled(drawlist, rect.Min, rect.Max, draw->get_clr(clr->child), SCALE(elements->child.rounding));

        gui->begin_content(header_buffer, ImVec2(gui->content_avail().x, SCALE(elements->child.header)), SCALE(0, 0), SCALE(0, 0));
        {
            rect = gui->get_window()->Rect();
            ImRect inner = ImRect(rect.Min + SCALE(elements->padding.x, 0), rect.Max - SCALE(elements->padding.x, 0));

            draw->rect_filled(drawlist, rect.Min, rect.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding));
            draw->text_clipped(drawlist, font->get(my_font, 12), inner.Min, inner.Max, draw->get_clr(clr->accent), name, 0, 0, {0, 0.5});
            draw->line(drawlist, rect.GetBL(), rect.GetBR(), draw->get_clr(clr->selection));
        }
        gui->end_content();

        gui->begin_content(widgets_buffer, ImVec2(gui->content_avail().x, 0), SCALE(0, 0), SCALE(0, 0),
                          window_flags_no_scroll_with_mouse | window_flags_no_scrollbar,
                          child_flags_always_auto_resize | child_flags_auto_resize_y);
    }

    // Automatic buffers cleared when function returns - no manual cleanup needed
}

void c_widgets::child2(const char* name)
{
    ImVec2 cursor_pos = gui->get_pos();
    ImVec2 content_region = gui->content_avail();
    float max_width = content_region.x;

    ImGuiWindow* parent_window = gui->get_window();
    if (parent_window && parent_window->ScrollbarY) {
        auto* style = &var->style;
        max_width -= style->scrollbar_size * 2;
    }

    if (parent_window) {
        float child_end_x = cursor_pos.x + elements->child.width;

        for (int i = 0; i < parent_window->DC.ChildWindows.Size; i++) {
            ImGuiWindow* child_win = parent_window->DC.ChildWindows[i];
            if (child_win && child_win->Pos.x > child_end_x) {
                float distance_to_object = child_win->Pos.x - child_end_x;
                float available_width = distance_to_object - SCALE(elements->padding.x);
                if (available_width > 0 && available_width < max_width) {
                    max_width = available_width;
                    break;
                }
            }
        }
    }

    // Use automatic buffers (not static - each call gets its own)
    char content_buffer[128];
    char header_buffer[32];
    char widgets_buffer[32];

    // Build the names in automatic buffers
    snprintf(content_buffer, sizeof(content_buffer), "%s##child", name);
    snprintf(header_buffer, sizeof(header_buffer), "header");
    snprintf(widgets_buffer, sizeof(widgets_buffer), "widgets");

    gui->begin_content(content_buffer, ImVec2(max_width, 0), SCALE(0, 0), SCALE(0, 0),
                      window_flags_no_scroll_with_mouse | window_flags_no_scrollbar | window_flags_no_move,
                      child_flags_always_auto_resize | child_flags_auto_resize_y);
    {
        ImDrawList* drawlist = gui->get_window()->DrawList;
        ImRect rect = gui->get_window()->Rect();

        if (rect.GetWidth() > max_width) {
            rect.Max.x = rect.Min.x + max_width;
        }

        draw->rect_filled(drawlist, rect.Min, rect.Max, draw->get_clr(clr->child), SCALE(elements->child.rounding));

        gui->begin_content(header_buffer, ImVec2(gui->content_avail().x, SCALE(elements->child.header)), SCALE(0, 0), SCALE(0, 0));
        {
            rect = gui->get_window()->Rect();
            ImRect inner = ImRect(rect.Min + SCALE(elements->padding.x, 0), rect.Max - SCALE(elements->padding.x, 0));
            draw->rect_filled(drawlist, rect.Min, rect.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding));
            draw->text_clipped(drawlist, font->get(my_font, 12), inner.Min, inner.Max, draw->get_clr(clr->accent), name, 0, 0, { 0, 0.5 });
            draw->line(drawlist, rect.GetBL(), rect.GetBR(), draw->get_clr(clr->selection));
        }
        gui->end_content();

        // Calculer l'espace restant pour les widgets après avoir ajusté la largeur
        float remaining_width = max_width;
        if (remaining_width > 0) {
            gui->begin_content(widgets_buffer, ImVec2(remaining_width, 0), SCALE(0, 0), SCALE(0, 0),
                              window_flags_no_scroll_with_mouse | window_flags_no_scrollbar,
                              child_flags_always_auto_resize | child_flags_auto_resize_y);
        }
    }

    // Automatic buffers cleared when function returns - no manual cleanup needed
}

void c_widgets::end_child()
{
    gui->end_content();
    gui->end_content();
}