#include "../headers/includes.h"
#include "../../../../includes/DllMain.h"
#include "gui/Gui.h"
#include <cstring>

// Helper for comparing const char* in std::map
struct cstr_less {
    bool operator()(const char* a, const char* b) const {
        return strcmp(a, b) < 0;
    }
};

void c_widgets::close_all_popups()
{
	Gui* gui = &Gui::getInstance();
	if (!gui->isOpen()) {
		for (auto& popup : widgets->popup_storage)
		{
			popup.open = false;
		}
	}
}

bool c_widgets::is_popup_open(const char* name)
{
	bool open = false;

	for (auto& popup : widgets->popup_storage)
	{
		if (strcmp(popup.name, name) == 0)
		{
			open = popup.alpha > 0;
			break;
		}
	}

	return open;
}

void c_widgets::open_popup(const char* name)
{
	bool exists = false;

	for (auto& popup : widgets->popup_storage)
	{
		if (strcmp(popup.name, name) == 0)
		{
			popup.open = true;
			exists = true;
			break;
		}
	}

	if (!exists)
	{
		popup_storage_t entry{};
		strncpy_s(entry.name, name, sizeof(entry.name) - 1);
		entry.open = true;
		entry.alpha = 0.f;
		entry.size = {};
		widgets->popup_storage.push_back(entry);
	}
}

void c_widgets::close_popup(const char* name)
{
	for (auto& popup : widgets->popup_storage)
	{
		if (strcmp(popup.name, name) == 0)
		{
			popup.open = false;
			break;
		}
	}
}

bool c_widgets::popup(const char* name, ImVec2 pos, ImVec2 size, float rounding, bool always)
{
	int i = -1;
	bool find = false;
	for (int k = 0; k < widgets->popup_storage.size(); ++k)
	{
		if (strcmp(widgets->popup_storage[k].name, name) == 0)
		{
			i = k;
			find = true;
			break;
		}
	}
	if (!find)
	{
		return false;
	}

	// Track popup state changes and window positions
	static std::map<const char*, bool, cstr_less> popup_was_open;
	static std::map<const char*, ImVec2, cstr_less> popup_window_positions;
	ImGuiWindow* current_window = gui->get_window();
	ImVec2 current_window_pos = current_window->Pos;

	bool was_open = popup_was_open[name];
	bool is_opening = widgets->popup_storage[i].open && !was_open;
	popup_was_open[name] = widgets->popup_storage[i].open;

	// Detect window movement and close popup if window moved
	if (popup_window_positions.find(name) != popup_window_positions.end())
	{
		ImVec2 last_pos = popup_window_positions[name];
		if (abs(current_window_pos.x - last_pos.x) > 1.0f || abs(current_window_pos.y - last_pos.y) > 1.0f)
		{
			// Window moved, close popup
			widgets->popup_storage[i].open = false;
		}
	}
	popup_window_positions[name] = current_window_pos;

	gui->easing(widgets->popup_storage[i].alpha, widgets->popup_storage[i].open ? 1.f : 0.f, 9.f, smooth_easing);
	if (widgets->popup_storage[i].alpha < 0.01f)
	{
		return false;
	}
	gui->push_var(style_var_alpha, widgets->popup_storage[i].alpha);

	// Force position only when popup is opening, otherwise allow free movement
	if (is_opening)
	{
		gui->set_next_window_pos(gui->adjust_window_pos(pos, widgets->popup_storage[i].size), gui_cond_always);
	}
	else
	{
		gui->set_next_window_pos(gui->adjust_window_pos(pos, widgets->popup_storage[i].size), gui_cond_once);
	}

	gui->set_next_window_size(size);
	gui->begin(widgets->popup_storage[i].name, nullptr, (size.y == 0 ? window_flags_always_auto_resize : 0) | window_flags_no_focus_on_appearing | window_flags_no_background | window_flags_no_decoration | window_flags_no_scrollbar | window_flags_no_scroll_with_mouse | window_flags_no_nav);
	widgets->popup_storage[i].size = gui->window_size();
	draw->rect_filled(gui->window_drawlist(), gui->window_pos(), gui->window_pos() + gui->window_size(), draw->get_clr(clr->child), rounding);
	draw->rect(gui->window_drawlist(), gui->window_pos(), gui->window_pos() + gui->window_size(), draw->get_clr(clr->selection), rounding);
	if (!always)
	{
		gui->set_window_focus();
		if (!ImRect(gui->window_pos(), gui->window_pos() + gui->window_size()).Contains(GetMousePos()) && (gui->mouse_clicked(0)))
		{
			widgets->popup_storage[i].open = false;
		}
	}
	return true;
}

bool c_widgets::popup2(const char* name, ImVec2 pos, ImVec2 size, float rounding, bool always, bool modal)
{
	int i = -1;
	bool find = false;

	for (int k = 0; k < widgets->popup_storage.size(); ++k)
	{
		if (strcmp(widgets->popup_storage[k].name, name) == 0)
		{
			i = k;
			find = true;
			break;
		}
	}

	if (!find)
	{
		return false;
	}

	gui->easing(widgets->popup_storage[i].alpha, widgets->popup_storage[i].open ? 1.f : 0.f, 9.f, smooth_easing);

	if (widgets->popup_storage[i].alpha < 0.01f)
	{
		return false;
	}

	gui->push_var(style_var_alpha, widgets->popup_storage[i].alpha);

	gui->set_next_window_pos(gui->adjust_window_pos(pos, widgets->popup_storage[i].size), gui_cond_once);
	gui->set_next_window_size(size);

	gui->begin(widgets->popup_storage[i].name, nullptr, (size.y == 0 ? window_flags_always_auto_resize : 0) | window_flags_no_focus_on_appearing | window_flags_no_background | window_flags_no_decoration | window_flags_no_scrollbar | window_flags_no_scroll_with_mouse | window_flags_no_nav);
	widgets->popup_storage[i].size = gui->window_size();

	draw->rect_filled(gui->window_drawlist(), gui->window_pos(), gui->window_pos() + gui->window_size(), draw->get_clr(clr->layout), rounding);
	draw->rect(gui->window_drawlist(), gui->window_pos(), gui->window_pos() + gui->window_size(), draw->get_clr(clr->selection), rounding);

	if (modal)
	{
		gui->set_window_focus();
	}
	else if (!always)
	{
		gui->set_window_focus();

		if (!ImRect(gui->window_pos(), gui->window_pos() + gui->window_size()).Contains(GetMousePos()) && (gui->mouse_clicked(0)))
		{
			widgets->popup_storage[i].open = false;
		}
	}

	return true;
}


void c_widgets::end_popup() {
	gui->end();
	gui->pop_var();
}