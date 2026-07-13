#pragma once
#include "includes.h"
#include "../headers/config.h"

#define IMGUI_DEFINE_MATH_OPERATORS

struct popup_storage_t
{
    char name[32];
    bool open;
    float alpha;
    ImVec2 size;
};

class c_widgets
{
public:

    bool modal_open = false;
    std::vector<popup_storage_t> popup_storage;

    void close_all_popups();

    bool is_popup_open(const char* name);
    void open_popup(const char* name);
    void close_popup(const char* name);
    bool popup(const char* name, ImVec2 pos, ImVec2 size, float rounding, bool always = false);
    bool popup2(const char* name, ImVec2 pos, ImVec2 size, float rounding, bool always = false, bool modal = false);
    void end_popup();

    bool checkbox(const char* name, bool* callback, ImVec4* color = nullptr, bool conditional = false);
    bool tab_section(const char* name, const std::vector<const char*>& variants, std::vector<int> tabs);
    bool dropdown_section(const char* name, int* callback, const std::vector<const char*>& variants);
    void child(const char* name);
    void child2(const char* name);
    void end_child();
    bool slider_float(const char* name, float* callback, float vmin, float vmax, const char* format = "%.1f");
    bool slider_int(const char* name, int* callback, int vmin, int vmax, const char* format = "%d");
    bool range_slider_float(const char* name, float* vmin_callback, float* vmax_callback, float range_min, float range_max, const char* format = "%.1f");
    bool range_slider_int(const char* name, int* vmin_callback, int* vmax_callback, int range_min, int range_max, const char* format = "%d");
    bool selectable(const char* name, bool selected);
    bool dropdown2(const char* name, int* callback, const std::vector<const char*>& variants, bool show_name, bool show_line);
    bool dropdown(const char* name, int *callback, const std::vector<const char*>& variants);
    bool multi_dropdown(const char* name, std::vector<bool>* callback, const std::vector<const char*>& variants);
    bool dropdown_section_ex(const char* name, int* callback, const std::vector<const char*>& variants, bool auto_close);
    bool colorpicker(const char* name, ImVec4* color);
    bool color_selector2(const char* name, ImVec4* color);
    bool color_selector(const char* name, ImVec4* color);
    bool cloud_gestion(const char* name, const char* description, const char* sharcode);
    bool config(const char* id, const char* name, const char* description, bool *loaded);
    bool cloud_config(const char* name, const char* description, const char* creator, const char* date, const char* share_code, int likes, int
                      dislikes, int downloads);
    bool config_manager();

    //bool keybind_button(const char* name, const char* button_text);

    bool text(const char* text, ImFont* font, ImColor col);
    bool text_line(const char* text, ImFont* font, ImColor col);
    bool config_text_field(const char* name, char* buf, int buf_size);
    bool config_text_field_search(const char* name, char* buf, int buf_size, bool* search_clicked);

    bool config_text_field_search_2(const char* name, char *buf, int buf_size, bool *search_clicked);

    bool full_config_text_field(const char* name, char* buf, int buf_size);
    bool config_text_field_2(const char* name, char* buf, int buf_size);

    bool config_text_field_3(const char* name, char *buf, int buf_size);

    bool button(const char* name);
    bool button3(const char* name, const char* text);
    bool button2(const char* name);
    bool fullButton(const char* name);
    bool keybind(const char* name, int* key, int* mode, bool show_label = true);
    void tooltip_bind(const char* label, const char* hint, int* key, int* mode);
};

inline std::unique_ptr<c_widgets> widgets = std::make_unique<c_widgets>();

// Forces any active slider click-to-type edit to exit immediately. Call this
// when the GUI closes so the input-block flag cannot survive a close/unload.
void slider_edit_force_exit();

class c_notify
{
public:

    enum class notify_type {
        success,
        warning,
        failed,
        info
    };

    void setup_notify();

    void add_notify(std::string_view text, notify_type type);


    // Nouvelles m�thodes � ajouter � la classe c_notify
    ImVec4 get_notify_colors(notify_type type, bool is_background);
    const char* get_notify_icon(notify_type type);
    void add_success(std::string_view text);
    void add_warning(std::string_view text);
    void add_error(std::string_view text);

    struct notify_state
    {
        int notify_id;
        std::string_view text;
        notify_type type{ c_notify::notify_type::success };

        ImVec2 window_size{ 0, 0 };
        float notify_alpha{ 0 };
        bool active_notify{ true };
        float notify_timer{ 0 };
        float notify_pos{ 0 };
    };

private:
    ImVec2 render_notify(int cur_notify_value, float notify_alpha, float notify_percentage, float notify_pos, std::string_view text, notify_type type);

    float notify_time{ 15 };
    int notify_count{ 0 };

    float notify_spacing{ 20 };
    ImVec2 notify_padding{ 20, 20 };

    std::vector<notify_state> notifications;

};

inline std::unique_ptr<c_notify> notify = std::make_unique<c_notify>();
