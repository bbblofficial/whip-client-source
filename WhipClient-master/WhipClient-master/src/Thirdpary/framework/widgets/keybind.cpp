#include "../headers/functions.h"
#include "../headers/widgets.h"
#include "task/impl/InputTask.h"
#include <Windows.h>

const char* keys[] =
{
    "None",
    "Mouse 1",
    "Mouse 2",
    "CN",
    "Mouse 3",
    "Mouse 4",
    "Mouse 5",
    "-",
    "Back",
    "Tab",
    "-",
    "-",
    "CLR",
    "Enter",
    "-",
    "-",
    "Shift",
    "CTL",
    "Menu",
    "Pause",
    "Caps Lock",
    "KAN",
    "-",
    "JUN",
    "FIN",
    "KAN",
    "-",
    "Escape",
    "CON",
    "NCO",
    "ACC",
    "MAD",
    "Space",
    "PGU",
    "PGD",
    "End",
    "Home",
    "Left",
    "Up",
    "Right",
    "Down",
    "SEL",
    "PRI",
    "EXE",
    "PRI",
    "INS",
    "Delete",
    "HEL",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "WIN",
    "WIN",
    "APP",
    "-",
    "SLE",
    "Num 0",
    "Num 1",
    "Num 2",
    "Num 3",
    "Num 4",
    "Num 5",
    "Num 6",
    "Num 7",
    "Num 8",
    "Num 9",
    "MUL",
    "ADD",
    "SEP",
    "MIN",
    "Delete",
    "DIV",
    "F1",
    "F2",
    "F3",
    "F4",
    "F5",
    "F6",
    "F7",
    "F8",
    "F9",
    "F10",
    "F11",
    "F12",
    "F13",
    "F14",
    "F15",
    "F16",
    "F17",
    "F18",
    "F19",
    "F20",
    "F21",
    "F22",
    "F23",
    "F24",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "NUM",
    "SCR",
    "EQU",
    "MAS",
    "TOY",
    "OYA",
    "OYA",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "LShift",
    "RShift",
    "LCtrl",
    "RCtrl",
    "LAlt",
    "RAlt"
};

struct key_state
{
    ImVec4 background, text;
    bool active = false;
    bool hovered = false;
    float alpha = 0.f;
};

static void getKeyDisplayName(int vk, char* outBuf, size_t bufSize) {
    if (vk <= 0 || vk >= 256) {
        strcpy_s(outBuf, bufSize, "None");
        return;
    }

    constexpr int staticCount = sizeof(keys) / sizeof(keys[0]);
    if (vk < staticCount) {
        const char* staticName = keys[vk];
        if (staticName && staticName[0] != '-' && staticName[0] != '\0') {
            strcpy_s(outBuf, bufSize, staticName);
            return;
        }
    }

    UINT scanCode = MapVirtualKeyA(vk, MAPVK_VK_TO_VSC);
    LPARAM lParam = static_cast<LPARAM>(scanCode) << 16;
    switch (vk) {
        case VK_RCONTROL: case VK_RMENU:
        case VK_LEFT: case VK_UP: case VK_RIGHT: case VK_DOWN:
        case VK_PRIOR: case VK_NEXT: case VK_END: case VK_HOME:
        case VK_INSERT: case VK_DELETE: case VK_DIVIDE: case VK_NUMLOCK:
            lParam |= (1LL << 24);
            break;
        default: break;
    }

    char winName[64] = {};
    if (GetKeyNameTextA(static_cast<LONG>(lParam), winName, sizeof(winName)) > 0) {
        strcpy_s(outBuf, bufSize, winName);
        return;
    }

    snprintf(outBuf, bufSize, "0x%02X", vk);
}

static void sendKeyUpToGame(HWND targetWindow, int keyCode) {
    UINT scanCode = MapVirtualKeyA(keyCode, MAPVK_VK_TO_VSC);
    LPARAM lParam = (scanCode << 16) | (1 << 30) | (1 << 31);

    PostMessageA(targetWindow, WM_KEYUP, keyCode, lParam);
}

static void releaseAllKeysToGame(HWND targetWindow) {
    for (int i = 0; i < 256; ++i) {
        if (GetAsyncKeyState(i) & 0x8000) {
            if (i == VK_LBUTTON || i == VK_RBUTTON || i == VK_MBUTTON ||
                i == VK_XBUTTON1 || i == VK_XBUTTON2) {
                continue;
            }
            sendKeyUpToGame(targetWindow, i);
        }
    }
}

static bool areAllKeysReleased() {
    for (int i = 0x08; i <= 0xFE; i++) {
        if (GetAsyncKeyState(i) & 0x8000) {
            return false;
        }
    }

    for (int i = 0; i < 5; i++) {
        int vkCode = 0;
        switch (i) {
        case 0: vkCode = VK_LBUTTON; break;
        case 1: vkCode = VK_RBUTTON; break;
        case 2: vkCode = VK_MBUTTON; break;
        case 3: vkCode = VK_XBUTTON1; break;
        case 4: vkCode = VK_XBUTTON2; break;
        }
        if (GetAsyncKeyState(vkCode) & 0x8000) {
            return false;
        }
    }

    return true;
}

bool c_widgets::keybind(const char* name, int* key, int* mode, bool show_label)
{
    struct keybind_state
    {
        ImVec4 background, text;
        ImVec4 cirlce_color, text_color;
        bool active = false;
        bool hovered = false;
        float alpha = 0.f;
        bool was_active = false;
        bool waiting_for_release = false;
        int pressed_key = 0;
        bool key_was_pressed = false;
        std::map<int, bool> previous_key_states;
        std::map<int, bool> previous_mouse_states;
    };

    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems)
        return false;

    ImGuiContext& g = *GImGui;
    ImGuiIO& io = g.IO;

    const ImGuiID id = window->GetID(name);
    keybind_state* state = gui->anim_container<keybind_state>(id);

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(gui->content_avail().x, SCALE(elements->checkbox.size));
    ImRect total(pos, pos + size);
    ImRect rect(total.Min + SCALE(elements->padding), total.Max - SCALE(elements->padding));

    char active_key_buf[64];
    getKeyDisplayName(*key, active_key_buf, sizeof(active_key_buf));
    const char* active_key = active_key_buf;

    char buf_display[64] = "None";
    bool value_changed = false;
    int k = *key;

    if (*key != 0 && g.ActiveId != id) {
        strcpy_s(buf_display, active_key);
    }
    else if (g.ActiveId == id) {
        strcpy_s(buf_display, "...");
    }

    PushFont(font->get(my_font, 11));
    const ImVec2 label_size = CalcTextSize(buf_display, NULL, true);
    PopFont();

    float buttonHeight = SCALE(elements->checkbox.button.y * 1.5);
    float minButtonWidth = SCALE(50);
    float horizontalPadding = SCALE(elements->padding.x);
    float buttonWidth = ImMax(minButtonWidth, label_size.x + (horizontalPadding * 2) + SCALE(8));
    float rightMargin = SCALE(elements->padding.x);

    ImRect button(
        ImVec2(rect.Max.x - buttonWidth - rightMargin, rect.GetCenter().y - buttonHeight / 2.0f),
        ImVec2(rect.Max.x - rightMargin, rect.GetCenter().y + buttonHeight / 2.0f)
    );

    gui->item_size(total);
    if (!gui->item_add(total, id))
        return false;

    bool hovered = ItemHoverable(button, id, NULL);

    if (IsKeyPressed(GetKeyIndex(ImGuiKey_Escape)) && state->was_active) {
        *key = 0;
        value_changed = true;
        ClearActiveID();
        InputTask_SetBlockGameInputs(false);
        state->was_active = false;
        state->waiting_for_release = false;
        state->pressed_key = 0;
        state->key_was_pressed = false;
        state->previous_key_states.clear();
        state->previous_mouse_states.clear();
    }

    ImVec4 bg_color = g.ActiveId == id || hovered ?
        ColorConvertU32ToFloat4(draw->get_clr(clr->selection)) :
        ColorConvertU32ToFloat4(draw->get_clr(clr->accent));

    ImVec4 text_color = g.ActiveId == id ?
        ColorConvertU32ToFloat4(draw->get_clr(clr->white)) :
        hovered ?
        ColorConvertU32ToFloat4(draw->get_clr(clr->white)) :
        ColorConvertU32ToFloat4(draw->get_clr(clr->text_inactive));

    state->background = ImLerp(state->background, bg_color, GetIO().DeltaTime * 6.f);
    state->text = ImLerp(state->text, text_color, GetIO().DeltaTime * 6.f);

    ImU32 labelColor = draw->get_clr(clr->white);
    draw->text_clipped(window->DrawList, font->get(my_font, 12),
        total.Min + SCALE(elements->padding.x, 0),
        ImVec2(button.Min.x - SCALE(5), total.Max.y),
        labelColor,
        name, 0, 0, { 0, 0.5 });

    draw->rect_filled(window->DrawList, button.Min, button.Max,
        draw->get_clr(clr->selection), SCALE(elements->dropdown.rounding));

    draw->text_clipped(window->DrawList, font->get(my_font, 11),
        button.Min + SCALE(elements->padding.x, 0),
        button.Max - SCALE(elements->padding.x, 0),
        draw->get_clr(clr->white),
        buf_display, 0, 0, { 0.5f, 0.5f });

    if (hovered && io.MouseClicked[0])
    {
        if (g.ActiveId != id) {
            HWND targetWindow = FindWindowA("LWJGL", nullptr);
            if (targetWindow) {
                releaseAllKeysToGame(targetWindow);
            }

            memset(io.MouseDown, 0, sizeof(io.MouseDown));
            memset(io.KeysDown, 0, sizeof(io.KeysDown));

            InputTask_SetBlockGameInputs(true);
            state->waiting_for_release = true;
            state->pressed_key = 0;
            state->key_was_pressed = false;
            state->previous_key_states.clear();
            state->previous_mouse_states.clear();
        }
        ImGui::SetActiveID(id, window);
        ImGui::FocusWindow(window);
        state->was_active = true;
    }
    else if (io.MouseClicked[0]) {
        if (g.ActiveId == id) {
            ImGui::ClearActiveID();
            InputTask_SetBlockGameInputs(false);
            state->was_active = false;
            state->waiting_for_release = false;
            state->pressed_key = 0;
            state->key_was_pressed = false;
        }
    }

    if (g.ActiveId == id) {
        ImGui::KeepAliveID(id);

        // Vérifier si toutes les touches sont relâchées
        if (state->waiting_for_release) {
            if (areAllKeysReleased()) {
                state->waiting_for_release = false;
            }
        }

        // Seulement détecter les nouvelles touches si on n'attend plus les relâchements
        if (!state->waiting_for_release) {
            // Détecter les pressions et relâchements de souris
            for (auto i = 0; i < 5; i++) {
                int vkCode = 0;
                switch (i) {
                case 0: vkCode = VK_LBUTTON; break;
                case 1: vkCode = VK_RBUTTON; break;
                case 2: vkCode = VK_MBUTTON; break;
                case 3: vkCode = VK_XBUTTON1; break;
                case 4: vkCode = VK_XBUTTON2; break;
                }

                bool currentState = (GetAsyncKeyState(vkCode) & 0x8000) != 0;
                bool previousState = state->previous_mouse_states[vkCode];

                // Détecter le DOWN (transition false -> true)
                if (currentState && !previousState) {
                    state->pressed_key = vkCode;
                    state->key_was_pressed = true;
                }

                // Détecter le UP (transition true -> false)
                if (!currentState && previousState && state->key_was_pressed && state->pressed_key == vkCode) {
                    switch (i) {
                    case 0: k = 0x01; break;
                    case 1: k = 0x02; break;
                    case 2: k = 0x04; break;
                    case 3: k = 0x05; break;
                    case 4: k = 0x06; break;
                    }
                    value_changed = true;
                    ImGui::ClearActiveID();
                    InputTask_SetBlockGameInputs(false);
                    state->was_active = false;
                    state->waiting_for_release = false;
                    state->pressed_key = 0;
                    state->key_was_pressed = false;
                }

                state->previous_mouse_states[vkCode] = currentState;
            }

            // Détecter les pressions et relâchements de clavier
            if (!value_changed) {
                for (auto i = 0x08; i <= 0xFE; i++) {
                    bool currentState = (GetAsyncKeyState(i) & 0x8000) != 0;
                    bool previousState = state->previous_key_states[i];

                    // Détecter le DOWN (transition false -> true)
                    if (currentState && !previousState) {
                        state->pressed_key = i;
                        state->key_was_pressed = true;
                    }

                    // Détecter le UP (transition true -> false)
                    if (!currentState && previousState && state->key_was_pressed && state->pressed_key == i) {
                        k = i;
                        value_changed = true;
                        ImGui::ClearActiveID();
                        InputTask_SetBlockGameInputs(false);
                        state->was_active = false;
                        state->waiting_for_release = false;
                        state->pressed_key = 0;
                        state->key_was_pressed = false;
                        break;
                    }

                    state->previous_key_states[i] = currentState;
                }
            }

            if (value_changed)
                *key = k;
        }
    }
    else if (state->was_active) {
        InputTask_SetBlockGameInputs(false);
        state->was_active = false;
        state->waiting_for_release = false;
        state->pressed_key = 0;
        state->key_was_pressed = false;
    }

    char popup_id[256];
    snprintf(popup_id, sizeof(popup_id), "%s_popup", name);

    if (hovered && g.IO.MouseClicked[1] || state->active &&
        (g.IO.MouseClicked[0] || g.IO.MouseClicked[1]) && !state->hovered)
    {
        if (widgets->is_popup_open(popup_id))
            widgets->close_popup(popup_id);
        else
            widgets->open_popup(popup_id);
    }

    state->alpha = ImClamp(state->alpha + (8.f * g.IO.DeltaTime * (state->active ? 1.f : -1.f)), 0.f, 1.f);

    if (widgets->popup(popup_id,
        ImVec2(button.GetCenter().x - SCALE(50), button.Max.y + SCALE(5)),
        ImVec2(SCALE(100), SCALE(100)),
        SCALE(elements->dropdown.rounding),
        false))
    {
        if (widgets->selectable("Hold", *mode == 0))
        {
            *mode = 0;
            widgets->close_popup(popup_id);
        }
        if (widgets->selectable("Toggle", *mode == 1))
        {
            *mode = 1;
            widgets->close_popup(popup_id);
        }
        if (widgets->selectable("Always", *mode == 2))
        {
            *mode = 2;
            widgets->close_popup(popup_id);
        }

        widgets->end_popup();
    }

    if (gui->content_avail().y + gui->get_window()->Scroll.y > 0)
    {
        draw->line(window->DrawList, total.GetBL(), total.GetBR(), draw->get_clr(clr->selection));
    }

    return value_changed;
}

void c_widgets::tooltip_bind(const char* label, const char* hint, int* key, int* mode)
{
    keybind(label, key, mode, true);

    ImGui::SetCursorPos(ImGui::GetCursorPos() - ImVec2(0, (ImGui::GetStyle().ItemSpacing.y / 2) + SCALE(4)));
    ImGui::PushStyleColor(ImGuiCol_Text, draw->get_clr(clr->text_inactive));

    ImGui::PushFont(font->get(my_font, 10));
    ImGui::Text(hint);
    ImGui::PopFont();

    ImGui::PopStyleColor();
}