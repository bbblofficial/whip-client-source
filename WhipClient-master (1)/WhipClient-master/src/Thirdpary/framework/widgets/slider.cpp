#include "../headers/includes.h"
#include "task/impl/InputTask.h"
#include <cstring>

// ─────────────────────────────────────────────────────────────────────────────
// Slider click-to-type edit system
//
// Only ONE slider can be in edit mode at a time — tracked by a single global
// ImGuiID. Every entry/exit transition goes through enter_edit_mode /
// exit_edit_mode, so the InputTask block flag stays consistent with the edit
// state. This eliminates the multi-state desync that previously caused stuck
// sliders / frozen game input.
// ─────────────────────────────────────────────────────────────────────────────
namespace {
    struct slider_edit_global {
        ImGuiID active_id = 0;  // 0 = no slider editing
        char    buf[32]   = {};
        int     frames    = 0;
        bool    need_focus = false;
    };

    slider_edit_global g_slider_edit;

    void exit_edit_mode() {
        if (g_slider_edit.active_id != 0) {
            g_slider_edit.active_id = 0;
            g_slider_edit.frames = 0;
            g_slider_edit.need_focus = false;
            std::memset(g_slider_edit.buf, 0, sizeof(g_slider_edit.buf));
            InputTask_SetBlockGameInputs(false);
            // Drop any ImGui active item so the InputText releases keyboard focus
            ImGui::ClearActiveID();
        }
    }

    void enter_edit_mode(ImGuiID id, const char* initial) {
        // Another slider was editing — release cleanly first so block flag is accurate
        if (g_slider_edit.active_id != 0 && g_slider_edit.active_id != id) {
            exit_edit_mode();
        }
        g_slider_edit.active_id = id;
        std::strncpy(g_slider_edit.buf, initial ? initial : "", sizeof(g_slider_edit.buf) - 1);
        g_slider_edit.buf[sizeof(g_slider_edit.buf) - 1] = '\0';
        g_slider_edit.frames = 0;
        g_slider_edit.need_focus = true;
        InputTask_SetBlockGameInputs(true);
    }

    // Returns true if user pressed Enter and buf contains the new value to commit.
    // Returns false otherwise (still editing, or just exited via Escape/click-outside).
    bool render_edit_input(ImGuiID slider_id, const ImRect& rect, const char* name) {
        ImGuiWindow* window = gui->get_window();

        // Label (same as normal draw path)
        draw->text_clipped(window->DrawList, font->get(my_font, 12), rect.Min, rect.Max,
                           draw->get_clr(clr->white), name, 0, 0, { 0, 0 });
        // Underline line as "hint" that this slot is live
        ImRect line(rect.GetBL() - SCALE(0, elements->slider.line_height), rect.Max);
        draw->rect_filled(window->DrawList, line.Min, line.Max,
                          draw->get_clr(clr->selection), SCALE(elements->slider.rounding));

        // Right-aligned InputText sized to its current content
        ImVec2 textSize = font->get(my_font, 12)->CalcTextSizeA(12.0f, FLT_MAX, 0.0f, g_slider_edit.buf);
        float  inputW   = ImMax(textSize.x + SCALE(8.0f), SCALE(24.0f));
        ImVec2 inputMin(rect.Max.x - inputW, rect.Min.y);

        ImVec2 savedCursor = ImGui::GetCursorScreenPos();
        ImGui::SetCursorScreenPos(inputMin);
        ImGui::PushItemWidth(inputW);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(SCALE(2.0f), SCALE(0.0f)));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, SCALE(2.0f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg,        ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_Text,           ImVec4(1, 1, 1, 1));
        ImGui::PushStyleColor(ImGuiCol_FrameBgActive,  ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0, 0, 0, 0));

        char inputId[64];
        snprintf(inputId, sizeof(inputId), "##slider_edit_%u", static_cast<unsigned>(slider_id));
        ImGuiID inputImGuiId = window->GetID(inputId);

        if (g_slider_edit.need_focus) {
            ImGui::SetKeyboardFocusHere();
            g_slider_edit.need_focus = false;
        }

        bool enter_pressed = ImGui::InputText(
            inputId, g_slider_edit.buf, sizeof(g_slider_edit.buf),
            ImGuiInputTextFlags_AutoSelectAll
            | ImGuiInputTextFlags_EnterReturnsTrue
            | ImGuiInputTextFlags_CharsDecimal);

        // Check active ID AFTER InputText has run so we see the post-processing value
        bool input_is_active = (ImGui::GetActiveID() == inputImGuiId);
        bool input_is_hovered = ImGui::IsItemHovered();

        ImGui::PopStyleColor(4);
        ImGui::PopStyleVar(2);
        ImGui::PopItemWidth();
        ImGui::SetCursorScreenPos(savedCursor);

        g_slider_edit.frames++;

        // ── Exit paths ──
        // 1. Enter committed → caller applies value & exits
        if (enter_pressed) {
            return true;
        }
        // 2. Escape always cancels
        if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            exit_edit_mode();
            return false;
        }
        // 3. Click outside our InputText (grace period to ignore the click that entered edit)
        if (g_slider_edit.frames > 2 && ImGui::IsMouseClicked(0) && !input_is_hovered) {
            exit_edit_mode();
            return false;
        }
        // 4. SAFETY NET: InputText lost ImGui active status without any of the above paths firing.
        //    Happens if another widget stole focus, window lost focus, context was reset, etc.
        //    Grace window of 3 frames so we don't race the first-frame focus acquisition.
        if (g_slider_edit.frames > 3 && !input_is_active) {
            exit_edit_mode();
            return false;
        }

        return false;
    }
}

// Publicly exposed — Gui.cpp calls this when the menu closes so a stuck
// edit state can never survive a menu close / focus loss / unload.
void slider_edit_force_exit() {
    exit_edit_mode();
}

// Returns true if the mouse click landed in `click_rect` this frame AND the mouse
// is also over `click_rect` (filters clicks that started outside).
static bool clicked_in(const ImRect& click_rect) {
    return gui->mouse_clicked(0) && click_rect.Contains(ImGui::GetMousePos());
}

// Format a value into `out` using a compact numeric representation that round-trips through
// atoi/atof regardless of the display format string (which may contain suffixes).
template <typename T>
static void format_value_for_edit(char* out, size_t out_size, T value) {
    if constexpr (std::is_same_v<T, int>) {
        snprintf(out, out_size, "%d", value);
    } else {
        // %g strips trailing zeros; fall back to %f if scientific notation would trigger.
        snprintf(out, out_size, "%g", static_cast<double>(value));
    }
}

template <typename T>
static T parse_value_for_commit(const char* buf, T vmin, T vmax) {
    T parsed;
    if constexpr (std::is_same_v<T, int>) {
        parsed = static_cast<T>(atoi(buf));
    } else {
        parsed = static_cast<T>(atof(buf));
    }
    return ImClamp(parsed, vmin, vmax);
}

template <typename T>
bool slider_ex(const char* name, T* callback, T vmin, T vmax, const char* format)
{
    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems) {
        return false;
    }
    ImGuiID id = window->GetID(name);

    struct slider_state {
        float position = 0.f;
        float callback_anim = 0.f;
    };
    slider_state* state = gui->anim_container<slider_state>(id);

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size(gui->content_avail().x, SCALE(elements->slider.height));
    ImRect total(pos, pos + size);
    ImRect rect(total.Min + SCALE(elements->padding), total.Max - SCALE(elements->padding));
    ImRect line(rect.GetBL() - SCALE(0, elements->slider.line_height), rect.Max);

    gui->item_size(total);
    gui->item_add(total, id);

    // ── Edit mode ──────────────────────────────────────────────────────────
    if (g_slider_edit.active_id == id) {
        if (render_edit_input(id, rect, name)) {
            // Commit: parse buffer, clamp, exit. Editor allows up to 10× the
            // slider max (positive ranges only) so users can type values above
            // the visible slider cap.
            const T edit_vmax = (vmax > T(0)) ? static_cast<T>(vmax * T(10)) : vmax;
            *callback = parse_value_for_commit<T>(g_slider_edit.buf, vmin, edit_vmax);
            exit_edit_mode();
        }
        if (gui->content_avail().y + gui->get_window()->Scroll.y > 0) {
            draw->line(window->DrawList, total.GetBL(), total.GetBR(), draw->get_clr(clr->selection));
        }
        return false;
    }

    // ── Normal slider mode ────────────────────────────────────────────────
    bool held, pressed = gui->button_behavior(line, id, nullptr, &held);

    const float normalized = ImSaturate((ImGui::GetMousePos().x - line.Min.x) / line.GetWidth());

    if (held) {
        *callback = ImClamp(static_cast<T>(vmin + normalized * (vmax - vmin)), vmin, vmax);
    }

    const float range = static_cast<float>(vmax - vmin);
    const float safe_normalized = (range > 0.0f)
        ? ImSaturate(static_cast<float>(*callback - vmin) / range) : 0.0f;
    gui->easing(state->position, safe_normalized, 24.f, smooth_easing);
    gui->easing(state->callback_anim, (float)*callback, 24.f, smooth_easing);

    draw->rect_filled(window->DrawList, line.Min, line.Max, draw->get_clr(clr->selection),
                      SCALE(elements->slider.rounding));

    if (state->position > 0.02f) {
        draw->rect_filled_multi_color(window->DrawList, line.Min,
            line.Min + ImVec2(line.GetWidth() * state->position, line.GetHeight()),
            draw->get_clr(clr->accent), draw->get_clr(clr->accent, 0.6f),
            draw->get_clr(clr->accent, 0.6f), draw->get_clr(clr->accent),
            SCALE(elements->slider.rounding));
    }

    float x = line.Min.x + line.GetWidth() * state->position;
    x = ImClamp(x, line.Min.x + SCALE(elements->slider.grab.x) / 2,
                   line.Max.x - SCALE(elements->slider.grab.x) / 2);

    ImRect grab(ImVec2(x - SCALE(elements->slider.grab.x) / 2,
                       line.GetCenter().y - SCALE(elements->slider.grab.y) / 2),
                ImVec2(x + SCALE(elements->slider.grab.x) / 2,
                       line.GetCenter().y + SCALE(elements->slider.grab.y) / 2));

    draw->circle_filled(window->DrawList, grab.GetCenter(), grab.GetHeight() / 2,
                        draw->get_clr(clr->white));

    char output_value[128];
    T converted;
    if constexpr (std::is_same_v<T, int>) {
        converted = static_cast<T>(std::round(state->callback_anim));
    } else {
        converted = static_cast<T>(state->callback_anim);
    }
    gui->get_fmt(output_value, 128, &converted, format);

    draw->text_clipped(window->DrawList, font->get(my_font, 12), rect.Min, rect.Max,
                       draw->get_clr(clr->white), name, 0, 0, { 0, 0 });
    draw->text_clipped(window->DrawList, font->get(my_font, 12), rect.Min, rect.Max,
                       draw->get_clr(clr->white), output_value, 0, 0, { 1, 0 });

    // Click on the value text to enter edit mode
    {
        ImVec2 textSize = font->get(my_font, 12)->CalcTextSizeA(12.0f, FLT_MAX, 0.0f, output_value);
        ImRect valueRect(
            ImVec2(rect.Max.x - textSize.x - SCALE(4.0f), rect.Min.y),
            ImVec2(rect.Max.x + SCALE(4.0f), rect.Min.y + textSize.y + SCALE(2.0f))
        );

        if (clicked_in(valueRect)) {
            char initial[32];
            format_value_for_edit<T>(initial, sizeof(initial), *callback);
            enter_edit_mode(id, initial);
        }
    }

    if (gui->content_avail().y + gui->get_window()->Scroll.y > 0) {
        draw->line(window->DrawList, total.GetBL(), total.GetBR(), draw->get_clr(clr->selection));
    }

    return held;
}

bool c_widgets::slider_float(const char* name, float* callback, float vmin, float vmax, const char* format)
{
    return slider_ex<float>(name, callback, vmin, vmax, format);
}

bool c_widgets::slider_int(const char* name, int* callback, int vmin, int vmax, const char* format)
{
    return slider_ex<int>(name, callback, vmin, vmax, format);
}

// ─────────────────────────────────────────────────────────────────────────────
// Range slider: min + max. Click on the min text to edit min, click on the max
// text to edit max. Uses the same single-global edit state keyed by a
// per-endpoint id derived from the slider's base ImGuiID.
// ─────────────────────────────────────────────────────────────────────────────
struct range_slider_state
{
    float min_position  = 0.f;
    float max_position  = 0.f;
    float min_callback  = 0.f;
    float max_callback  = 0.f;
    int   active_grab   = 0; // 0 = none, 1 = min, 2 = max
};

template <typename T>
bool range_slider_ex(const char* name, T* vmin_callback, T* vmax_callback, T range_min, T range_max, const char* format)
{
    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems) {
        return false;
    }
    ImGuiID id = window->GetID(name);
    // Derive stable sub-ids for the min/max edit targets
    ImGuiID id_min = id ^ 0x9E3779B9u;
    ImGuiID id_max = id ^ 0x517CC1B7u;

    range_slider_state* state = gui->anim_container<range_slider_state>(id);

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size(gui->content_avail().x, SCALE(elements->slider.height));
    ImRect total(pos, pos + size);
    ImRect rect(total.Min + SCALE(elements->padding), total.Max - SCALE(elements->padding));
    ImRect line(rect.GetBL() - SCALE(0, elements->slider.line_height), rect.Max);

    gui->item_size(total);
    gui->item_add(total, id);

    // Normalize values
    if (*vmin_callback > *vmax_callback) {
        T temp = *vmin_callback;
        *vmin_callback = *vmax_callback;
        *vmax_callback = temp;
    }
    *vmin_callback = ImClamp(*vmin_callback, range_min, range_max);
    *vmax_callback = ImClamp(*vmax_callback, range_min, range_max);

    const float range = static_cast<float>(range_max - range_min);
    const float safe_min_normalized = (range > 0.0f)
        ? ImSaturate(static_cast<float>(*vmin_callback - range_min) / range) : 0.0f;
    const float safe_max_normalized = (range > 0.0f)
        ? ImSaturate(static_cast<float>(*vmax_callback - range_min) / range) : 1.0f;

    gui->easing(state->min_position, safe_min_normalized, 24.f, smooth_easing);
    gui->easing(state->max_position, safe_max_normalized, 24.f, smooth_easing);
    gui->easing(state->min_callback, (float)*vmin_callback, 24.f, smooth_easing);
    gui->easing(state->max_callback, (float)*vmax_callback, 24.f, smooth_easing);

    // ── If either endpoint is in edit mode, render a single input for that endpoint ──
    if (g_slider_edit.active_id == id_min || g_slider_edit.active_id == id_max) {
        bool editing_min = (g_slider_edit.active_id == id_min);
        ImGuiID active = g_slider_edit.active_id;
        if (render_edit_input(active, rect, name)) {
            // Editor allows up to 10× the outer range max (positive only).
            const T edit_range_max = (range_max > T(0)) ? static_cast<T>(range_max * T(10)) : range_max;
            T clamped;
            if (editing_min) {
                // Min endpoint can rise up to the extended range; if it passes
                // the current max, bump the max so min ≤ max stays valid.
                T parsed = parse_value_for_commit<T>(g_slider_edit.buf, range_min, edit_range_max);
                clamped = parsed;
                *vmin_callback = clamped;
                if (*vmax_callback < *vmin_callback) *vmax_callback = *vmin_callback;
            } else {
                T parsed = parse_value_for_commit<T>(g_slider_edit.buf, *vmin_callback, edit_range_max);
                clamped = parsed;
                *vmax_callback = clamped;
            }
            exit_edit_mode();
        }
        if (gui->content_avail().y + gui->get_window()->Scroll.y > 0) {
            draw->line(window->DrawList, total.GetBL(), total.GetBR(), draw->get_clr(clr->selection));
        }
        return false;
    }

    const float grab_size = SCALE(elements->slider.grab.x);
    float min_x = line.Min.x + line.GetWidth() * state->min_position;
    float max_x = line.Min.x + line.GetWidth() * state->max_position;

    min_x = ImClamp(min_x, line.Min.x + grab_size / 2, line.Max.x - grab_size / 2);
    max_x = ImClamp(max_x, line.Min.x + grab_size / 2, line.Max.x - grab_size / 2);

    ImRect min_grab(ImVec2(min_x - grab_size / 2, line.GetCenter().y - SCALE(elements->slider.grab.y) / 2),
                    ImVec2(min_x + grab_size / 2, line.GetCenter().y + SCALE(elements->slider.grab.y) / 2));
    ImRect max_grab(ImVec2(max_x - grab_size / 2, line.GetCenter().y - SCALE(elements->slider.grab.y) / 2),
                    ImVec2(max_x + grab_size / 2, line.GetCenter().y + SCALE(elements->slider.grab.y) / 2));

    bool min_held = false, max_held = false;

    char min_id_str[256];
    char max_id_str[256];
    snprintf(min_id_str, sizeof(min_id_str), "%s_min", name);
    snprintf(max_id_str, sizeof(max_id_str), "%s_max", name);

    ImGuiID min_btn_id = ImGui::GetID(min_id_str);
    ImGuiID max_btn_id = ImGui::GetID(max_id_str);

    bool grabs_overlap = (fabsf(min_x - max_x) < grab_size * 0.5f);

    if (grabs_overlap) {
        ImRect combined_grab(
            ImVec2(ImMin(min_grab.Min.x, max_grab.Min.x), min_grab.Min.y),
            ImVec2(ImMax(min_grab.Max.x, max_grab.Max.x), min_grab.Max.y));

        bool combined_held = false;
        gui->button_behavior(combined_grab, min_btn_id, nullptr, &combined_held);

        if (!ImGui::IsMouseDown(0)) {
            state->active_grab = 0;
        } else if (state->active_grab == 0 && combined_held) {
            if (safe_max_normalized >= 0.99f)      state->active_grab = 1;
            else if (safe_min_normalized <= 0.01f) state->active_grab = 2;
            else {
                float mouseX = ImGui::GetMousePos().x;
                float sliderCenter = (line.Min.x + line.Max.x) * 0.5f;
                state->active_grab = (mouseX <= sliderCenter) ? 1 : 2;
            }
        }

        min_held = combined_held && state->active_grab == 1;
        max_held = combined_held && state->active_grab == 2;
    } else {
        gui->button_behavior(max_grab, max_btn_id, nullptr, &max_held);
        gui->button_behavior(min_grab, min_btn_id, nullptr, &min_held);

        if (!ImGui::IsMouseDown(0)) {
            state->active_grab = 0;
        } else if (state->active_grab == 0) {
            if (min_held) state->active_grab = 1;
            else if (max_held) state->active_grab = 2;
        }
    }

    bool held = min_held || max_held;

    if (state->active_grab != 0) {
        const float normalized = ImSaturate((ImGui::GetMousePos().x - line.Min.x) / line.GetWidth());

        if (state->active_grab == 1) {
            *vmin_callback = ImClamp(static_cast<T>(range_min + normalized * range), range_min, *vmax_callback);
        } else if (state->active_grab == 2) {
            *vmax_callback = ImClamp(static_cast<T>(range_min + normalized * range), *vmin_callback, range_max);
        }
    }

    // Background + filled range + grabs
    draw->rect_filled(window->DrawList, line.Min, line.Max, draw->get_clr(clr->selection),
                      SCALE(elements->slider.rounding));

    if (state->max_position - state->min_position > 0.02f) {
        ImVec2 range_min_pos = ImVec2(line.Min.x + line.GetWidth() * state->min_position, line.Min.y);
        ImVec2 range_max_pos = ImVec2(line.Min.x + line.GetWidth() * state->max_position, line.Max.y);
        draw->rect_filled_multi_color(window->DrawList, range_min_pos, range_max_pos,
            draw->get_clr(clr->accent), draw->get_clr(clr->accent, 0.6f),
            draw->get_clr(clr->accent, 0.6f), draw->get_clr(clr->accent),
            SCALE(elements->slider.rounding));
    }

    draw->circle_filled(window->DrawList, min_grab.GetCenter(), min_grab.GetHeight() / 2, draw->get_clr(clr->white));
    draw->circle_filled(window->DrawList, max_grab.GetCenter(), max_grab.GetHeight() / 2, draw->get_clr(clr->white));

    // Format values
    char min_output[64], max_output[64];
    T min_converted, max_converted;
    if constexpr (std::is_same_v<T, int>) {
        min_converted = static_cast<T>(std::round(state->min_callback));
        max_converted = static_cast<T>(std::round(state->max_callback));
    } else {
        min_converted = static_cast<T>(state->min_callback);
        max_converted = static_cast<T>(state->max_callback);
    }
    gui->get_fmt(min_output, 64, &min_converted, format);
    gui->get_fmt(max_output, 64, &max_converted, format);

    char combined_output[128];
    snprintf(combined_output, 128, "%s - %s", min_output, max_output);

    // Label + combined value text
    draw->text_clipped(window->DrawList, font->get(my_font, 12), rect.Min, rect.Max,
                       draw->get_clr(clr->white), name, 0, 0, { 0, 0 });
    draw->text_clipped(window->DrawList, font->get(my_font, 12), rect.Min, rect.Max,
                       draw->get_clr(clr->white), combined_output, 0, 0, { 1, 0 });

    // Click regions for each value (min / max) — right-aligned layout
    {
        ImFont* f = font->get(my_font, 12);
        ImVec2 sMin = f->CalcTextSizeA(12.0f, FLT_MAX, 0.0f, min_output);
        ImVec2 sSep = f->CalcTextSizeA(12.0f, FLT_MAX, 0.0f, " - ");
        ImVec2 sMax = f->CalcTextSizeA(12.0f, FLT_MAX, 0.0f, max_output);
        float total_w = sMin.x + sSep.x + sMax.x;
        float start_x = rect.Max.x - total_w;

        ImRect minRect(ImVec2(start_x - SCALE(2.0f),             rect.Min.y),
                       ImVec2(start_x + sMin.x + SCALE(2.0f),    rect.Min.y + sMin.y + SCALE(2.0f)));
        ImRect maxRect(ImVec2(start_x + sMin.x + sSep.x - SCALE(2.0f), rect.Min.y),
                       ImVec2(rect.Max.x + SCALE(4.0f),          rect.Min.y + sMax.y + SCALE(2.0f)));

        if (clicked_in(minRect)) {
            char initial[32];
            format_value_for_edit<T>(initial, sizeof(initial), *vmin_callback);
            enter_edit_mode(id_min, initial);
        } else if (clicked_in(maxRect)) {
            char initial[32];
            format_value_for_edit<T>(initial, sizeof(initial), *vmax_callback);
            enter_edit_mode(id_max, initial);
        }
    }

    if (gui->content_avail().y + gui->get_window()->Scroll.y > 0) {
        draw->line(window->DrawList, total.GetBL(), total.GetBR(), draw->get_clr(clr->selection));
    }

    return held;
}

bool c_widgets::range_slider_float(const char* name, float* vmin_callback, float* vmax_callback, float range_min, float range_max, const char* format)
{
    return range_slider_ex<float>(name, vmin_callback, vmax_callback, range_min, range_max, format);
}

bool c_widgets::range_slider_int(const char* name, int* vmin_callback, int* vmax_callback, int range_min, int range_max, const char* format)
{
    return range_slider_ex<int>(name, vmin_callback, vmax_callback, range_min, range_max, format);
}
