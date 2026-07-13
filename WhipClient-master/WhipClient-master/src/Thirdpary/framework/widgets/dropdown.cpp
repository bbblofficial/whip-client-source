#include "../headers/includes.h"
#include "util/ClientStrings.h"

bool dropdown_ex2(const char* name, const char* preview, bool show_name = false, bool show_line = false)
{
    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems)
        return false;

    const ImGuiID id = window->GetID(name);

    // Utiliser une taille fixe comme pour un bouton
    ImVec2 size = SCALE(75, 30);
    const ImRect rect(window->DC.CursorPos, window->DC.CursorPos + size);

    // Utiliser les m�mes fonctions que le bouton pour l'ajout d'item
    gui->item_size(rect);
    if (!gui->item_add(rect, id))
        return false;

    // Traitement du comportement du bouton
    bool hovered, held;
    bool pressed = gui->button_behavior(rect, id, &hovered, &held);

    // Dessin du bouton
    draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->child), SCALE(elements->child.rounding));

    // Afficher le texte centr�
    draw->text_clipped(window->DrawList, font->get(my_font, 11), rect.Min, rect.Max, draw->get_clr(clr->white), preview, 0, 0, { 0.5, 0.5 });

    // Si press�, ouvrir le popup
    char popup_id[64];
    snprintf(popup_id, sizeof(popup_id), "%u", id);

    if (pressed)
    {
        widgets->open_popup(popup_id);
    }

    // Configuration du popup
    gui->push_var(style_var_window_padding, SCALE(elements->padding));
    gui->push_var(style_var_item_spacing, SCALE(elements->padding));

    // Afficher le popup sous le bouton
    if (widgets->popup(popup_id, rect.Min, ImVec2(rect.GetWidth(), 0), SCALE(elements->child.rounding)))
    {
        return true;
    }

    return false;
}

bool dropdown_ex(const char* name, const char* preview)
{
    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems)
    {
        return false;
    }
    ImGuiID id = window->GetID(name);
    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(gui->content_avail().x, SCALE(elements->dropdown.height));
    ImRect total(pos, pos + size);
    ImRect rect(total.Min + SCALE(elements->padding), total.Max - SCALE(elements->padding));
    ImRect button(rect.GetBL() - SCALE(0, elements->dropdown.button_height), rect.Max);
    gui->item_size(total);
    gui->item_add(total, id);
    bool pressed = gui->button_behavior(button, id, nullptr, nullptr);

    char popup_id[64];
    snprintf(popup_id, sizeof(popup_id), "%u", id);

    if (pressed)
    {
        widgets->open_popup(popup_id);
    }

    draw->text_clipped(window->DrawList, font->get(my_font, 12), rect.Min, rect.Max, draw->get_clr(clr->white), name, 0, 0, { 0, 0 });
    draw->rect_filled(window->DrawList, button.Min, button.Max, draw->get_clr(clr->selection), SCALE(elements->dropdown.rounding));
    draw->text_clipped(window->DrawList, font->get(my_font, 11), button.Min + SCALE(elements->padding.x, 0), button.Max, draw->get_clr(clr->white), preview, 0, 0, { 0, 0.5 });
    ImRect arrow = ImRect(button.GetTR() - SCALE(8 + elements->padding.x, 0), button.GetBR() - SCALE(elements->padding.x, 0));
    draw->rotate_start(window->DrawList);
    draw->text_clipped(window->DrawList, font->get(icon_font, 8), arrow.Min, arrow.Max, draw->get_clr(clr->text_inactive), Strings::iconDown(), 0, 0, { 0.5, 0.5 });
    draw->rotate_end(window->DrawList, 360.f, arrow.GetCenter());
    if (gui->content_avail().y + gui->get_window()->Scroll.y > 0)
    {
        draw->line(window->DrawList, total.GetBL(), total.GetBR(), draw->get_clr(clr->selection));
    }
    gui->push_var(style_var_window_padding, SCALE(elements->padding));
    gui->push_var(style_var_item_spacing, SCALE(elements->padding));

    // Pass current button position (recalculated each frame)
    if (widgets->popup(popup_id, button.Min, ImVec2(button.GetWidth(), 0), SCALE(elements->child.rounding)))
    {
        return true;
    }
    else
    {
        return false;
    }
}

void end_dropdown()
{
    widgets->end_popup();
}

bool c_widgets::dropdown2(const char* name, int* callback, const std::vector<const char*>& variants, bool show_name = false, bool show_line = false)
{
    // V�rifications de s�curit�
    if (callback == nullptr || variants.empty() || *callback < 0 || *callback >= variants.size())
    {
        *callback = 0; // S�curiser l'index
        return false;
    }

    bool value_changed = false;

    if (dropdown_ex2(name, variants[*callback], show_name, show_line))
    {
        for (int i = 0; i < variants.size(); ++i)
        {
            if (widgets->selectable(variants[i], *callback == i))
            {
                *callback = i;
                value_changed = true;
            }
        }
        end_dropdown();
    }

    gui->pop_var(2);

    return value_changed;
}

bool c_widgets::dropdown(const char* name, int *callback, const std::vector<const char*>& variants)
{

    if (!callback) return false;
    if (variants.empty()) return false;
    if (*callback < 0 || *callback >= variants.size()) return false;

    bool value_changed = false;

    if (dropdown_ex(name, variants[*callback]))
    {
        for (int i = 0; i < variants.size(); ++i)
        {
            if (widgets->selectable(variants[i], *callback == i))
            {
                *callback = i;
                value_changed = true;
            }
        }
        end_dropdown();
    }

    gui->pop_var(2);

    return value_changed;
}

bool c_widgets::multi_dropdown(const char* name, std::vector<bool>* callback, const std::vector<const char*>& variants)
{
    char preview[128];
    strcpy_s(preview, sizeof(preview), "Select");
    bool value_changed = false;

	for (size_t i = 0; i < variants.size(); ++i)
	{
		if (callback->at(i))
		{
			if (strcmp(preview, "Select") == 0) {
				strcpy_s(preview, sizeof(preview), variants[i]);
			}
			else {
				// Append ", " + variants[i]
				size_t current_len = strlen(preview);
				size_t remaining = sizeof(preview) - current_len - 1;
				if (remaining > 0) {
					strncat_s(preview, sizeof(preview), ", ", remaining);
					remaining = sizeof(preview) - strlen(preview) - 1;
					if (remaining > 0) {
						strncat_s(preview, sizeof(preview), variants[i], remaining);
					}
				}
			}

			if (strlen(preview) > 25)
			{
				preview[22] = '.';
				preview[23] = '.';
				preview[24] = '.';
				preview[25] = '\0';
				break;
			}
		}
	}

    if (dropdown_ex(name, preview))
    {
        for (int i = 0; i < variants.size(); ++i)
        {
            if (widgets->selectable(variants[i], callback->at(i)))
            {
                callback->at(i) = !callback->at(i);
                value_changed = true;
            }
        }
        end_dropdown();
    }

    gui->pop_var(2);

    return value_changed;
}