#include "../headers/includes.h"
#include "../../../../includes/DllMain.h"
#include "../../../../includes/manager/ConfigManager.h"
#include "../../../../includes/task/impl/InputTask.h"
#include "util/ClientStrings.h"
#include <thread>
#include <atomic>

struct config_state
{
    float alpha;
};

static bool needsRefresh = true;

// Background thread pour les opérations config sans bloquer le rendu
static std::atomic<bool> s_workerBusy{false};
static std::atomic<bool> s_workerDone{false};
static std::vector<ConfigInfo> s_listResult;

enum ConfigAction { ACTION_NONE, ACTION_LIST, ACTION_SAVE, ACTION_LOAD, ACTION_DEL, ACTION_MOD };
static ConfigAction s_action = ACTION_NONE;

bool c_widgets::config(const char* configId, const char* name, const char* description, bool* loaded)
{
    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems)
    {
        return false;
    }
    ImGuiID id = window->GetID(configId);
    config_state* state = gui->anim_container<config_state>(id);

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(gui->content_avail().x - SCALE(elements->padding.x), SCALE(elements->config.size));
    ImRect rect(pos, pos + size);
    ImRect inner(rect.Min + SCALE(elements->padding), rect.Max - SCALE(elements->padding));

    gui->item_size(rect);
    gui->item_add(rect, id);

    ImRect button(inner.GetTR() - ImVec2(inner.GetHeight(), 0), inner.GetBR());
    ImRect reload(button.GetTL() - ImVec2(inner.GetHeight() + SCALE(elements->padding.x), 0), button.GetBL() - SCALE(elements->padding.x, 0));
    ImRect deleter(reload.GetTL() - ImVec2(inner.GetHeight() + SCALE(elements->padding.x), 0), reload.GetBL() - SCALE(elements->padding.x, 0));

    bool pressed = gui->button_behavior(rect, id, nullptr, nullptr);

    // Gérer les clics sur les différents boutons (sur thread background)
    if (pressed && !s_workerBusy.load()) {
        ImVec2 mousePos = GetMousePos();

        if (deleter.Contains(mousePos)) {
            s_workerBusy.store(true);
            s_action = ACTION_DEL;
            std::string id = configId;
            std::thread([id]() {
                ConfigManager::getInstance().deleteConfig(id);
                s_workerDone.store(true);
                s_workerBusy.store(false);
            }).detach();
            *loaded = false;
        }
        else if (reload.Contains(mousePos)) {
            s_workerBusy.store(true);
            s_action = ACTION_MOD;
            std::string id = configId;
            std::thread([id]() {
                ConfigManager::getInstance().modifyConfig(id);
                s_workerDone.store(true);
                s_workerBusy.store(false);
            }).detach();
        }
        else if (button.Contains(mousePos)) {
            if (!*loaded) {
                s_workerBusy.store(true);
                s_action = ACTION_LOAD;
                std::string id = configId;
                std::thread([id]() {
                    ConfigManager::getInstance().loadConfig(id);
                    s_workerDone.store(true);
                    s_workerBusy.store(false);
                }).detach();
            }
        }
    }

    draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->child), SCALE(elements->child.rounding));
    draw->text_clipped(window->DrawList, font->get(my_font, 12), inner.Min, inner.Max, draw->get_clr(clr->white), name, 0, 0, {0, 0});
    draw->text_clipped(window->DrawList, font->get(my_font, 12), inner.Min, inner.Max, draw->get_clr(clr->text_inactive), description, 0, 0, {0, 1});

    gui->easing(state->alpha, *loaded ? 1.f : 0.f, 6.f, smooth_easing);

    draw->rect_filled(window->DrawList, button.Min, button.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding));
    draw->rect_filled(window->DrawList, button.Min + SCALE(elements->padding / 2), button.Max - SCALE(elements->padding / 2), draw->get_clr(clr->accent, state->alpha), SCALE(elements->child.rounding));

    draw->rect_filled(window->DrawList, reload.Min, reload.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding));
    draw->text_clipped(window->DrawList, font->get(custom_icon_font, 14), reload.Min, reload.Max, draw->get_clr(clr->text_inactive), "A", 0, 0, {0.5, 0.5});

    draw->rect_filled(window->DrawList, deleter.Min, deleter.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding));
    draw->text_clipped(window->DrawList, font->get(custom_icon_font, 12), deleter.Min, deleter.Max, draw->get_clr(clr->text_inactive), "B", 0, 0, {0.5, 0.5});

    return pressed;
}

bool c_widgets::cloud_config(const char* name, const char* description, const char* creator, const char* date, const char* share_code, int likes, int dislikes, int downloads)
{

    struct cloud_config_state
    {
        bool always;
        char name1[64];
        char name2[64];
    };

    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems)
    {
        return false;
    }
    ImGuiID id = window->GetID(name);
    cloud_config_state* state = gui->anim_container<cloud_config_state>(id);

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(gui->content_avail().x - SCALE(elements->padding.x), SCALE(elements->config.size));
    ImRect rect(pos, pos + size);
    ImRect inner(rect.Min + SCALE(elements->padding), rect.Max - SCALE(elements->padding));

    gui->item_size(rect);
    gui->item_add(rect, id);

    bool pressed = gui->button_behavior(rect, id, nullptr, nullptr);

    draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->child), SCALE(elements->child.rounding));
    draw->text_clipped(window->DrawList, font->get(my_font, 12), inner.Min, inner.Max, draw->get_clr(clr->white), name, 0, 0, {0, 0});
    draw->text_clipped(window->DrawList, font->get(my_font, 12), inner.Min, inner.Max, draw->get_clr(clr->text_inactive), description, 0, 0, {0, 1});

    ImRect download(inner.GetTR() - ImVec2(inner.GetHeight(), 0), inner.GetBR());

    draw->rect_filled(window->DrawList, download.Min, download.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding));
    draw->text_clipped(window->DrawList, font->get(custom_icon_font, 11), download.Min, download.Max, draw->get_clr(clr->text_inactive), "C", 0, 0, {0.5, 0.5});

    ImRect dislike(download.GetTL() - ImVec2(inner.GetHeight() + SCALE(elements->padding.x), 0), download.GetBL() - SCALE(elements->padding.x, 0));

    draw->rect_filled(window->DrawList, dislike.Min, dislike.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding));
    draw->text_clipped(window->DrawList, font->get(custom_icon_font, 11), dislike.Min, dislike.Max, draw->get_clr(clr->text_inactive), "E", 0, 0, {0.5, 0.5});

    ImRect like(dislike.GetTL() - ImVec2(inner.GetHeight() + SCALE(elements->padding.x), 0), dislike.GetBL() - SCALE(elements->padding.x, 0));

    draw->rect_filled(window->DrawList, like.Min, like.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding));
    draw->text_clipped(window->DrawList, font->get(custom_icon_font, 11), like.Min, like.Max, draw->get_clr(clr->text_inactive), "F", 0, 0, {0.5, 0.5});

    ImRect file(like.GetTL() - ImVec2(inner.GetHeight() + SCALE(elements->padding.x), 0), like.GetBL() - SCALE(elements->padding.x, 0));

    draw->rect_filled(window->DrawList, file.Min, file.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding));
    draw->text_clipped(window->DrawList, font->get(custom_icon_font, 11), file.Min, file.Max, draw->get_clr(clr->text_inactive), "D", 0, 0, {0.5, 0.5});

    char name_popup_id[128];
    snprintf(name_popup_id, sizeof(name_popup_id), "%s##popup", name);
    ImGuiID popup_id = window->GetID(name_popup_id);

    char popup_name[64];
    snprintf(popup_name, sizeof(popup_name), "%u", popup_id);

    if (file.Contains(GetMousePos()) && gui->mouse_clicked(0) && gui->is_item_hovered(0))
    {
        widgets->open_popup(popup_name);
    }

    if (widgets->is_popup_open(state->name1) || widgets->is_popup_open(state->name2))
    {
        state->always = true;
    }
    else
    {
        state->always = false;
    }

    gui->push_var(style_var_window_padding, SCALE(0, 0));
    gui->push_var(style_var_item_spacing, SCALE(0, 0));

    if (widgets->popup(popup_name, file.Min, SCALE(400, 300), SCALE(elements->child.rounding), state->always))
    {
        static int module_selected = 0;

        gui->begin_content("left", ImVec2(SCALE(150), gui->content_avail().y), SCALE(elements->padding), SCALE(elements->padding), window_flags_no_scroll_with_mouse | window_flags_no_scrollbar);
        {
            widgets->text(creator, font->get(my_font, 14), clr->white);

            gui->set_pos(gui->get_pos().x - SCALE(elements->padding.x), pos_x);
            gui->begin_content("dropdowns", ImVec2(SCALE(150), gui->content_avail().y), SCALE(0, 0), SCALE(0, 0), window_flags_no_scroll_with_mouse | window_flags_no_scrollbar);

            static int detail_selected = 0;
            static const char* detail_options[] = {"One", "Two", "Three"};
            widgets->dropdown("Details", &detail_selected, std::vector<const char*>(std::begin(detail_options), std::end(detail_options)));
            snprintf(state->name1, sizeof(state->name1), "%u", gui->get_window()->GetID("Details"));

            static const char* module_options[] = {"One", "Two", "Three"};
            widgets->dropdown("Affected Module", &module_selected, std::vector<const char*>(std::begin(module_options), std::end(module_options)));
            snprintf(state->name2, sizeof(state->name2), "%u", gui->get_window()->GetID("Affected Module"));

            gui->end_content();

            draw->line(gui->foreground_drawlist(), gui->get_window()->Rect().GetTR(),  gui->get_window()->Rect().GetBR(), draw->get_clr(clr->selection));
        }
        gui->end_content();

        gui->sameline();

        gui->begin_content("right", ImVec2(SCALE(250), gui->content_avail().y), SCALE(elements->padding), SCALE(elements->padding));
        {
            widgets->text(name, font->get(my_font, 14), clr->white);

            if (module_selected != 0)
            {
                struct DataItem {
                    const char* name;
                    struct { const char* key; const char* value; } items[3];
                    int item_count;
                };

                DataItem data[] = {
                    { "Aimbot", { {"Slider", "10"}, {"Button", "On"}, {"Dropdown", "Val1"} }, 3 },
                    { "Visuals", { {"Slider", "10"}, {"Button", "On"}, {"Dropdown", "Val1"} }, 3 },
                };

                for (int i = 0; i < 2; ++i)
                {
                    gui->dummy(ImVec2(gui->content_avail().x, SCALE(24)));
                    ImRect mdrect(GetItemRectMin(), GetItemRectMax());
                    draw->rect_filled(gui->window_drawlist(), mdrect.Min, mdrect.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding), draw_flags_round_corners_top);
                    draw->text_clipped(gui->window_drawlist(), font->get(my_font, 12), mdrect.Min + SCALE(elements->padding.x, 0), mdrect.Max, draw->get_clr(clr->white), data[i].name, 0, 0, {0, 0.5});

                    gui->set_pos(gui->get_pos().y - SCALE(elements->padding.y), pos_y);
                    gui->begin_content(data[i].name, ImVec2(gui->content_avail().x, 0), SCALE(0, 0), SCALE(0, 0), window_flags_no_scroll_with_mouse | window_flags_no_scrollbar, child_flags_always_auto_resize | child_flags_auto_resize_y);
                    {
                        for (int k = 0; k < data[i].item_count; ++k)
                        {
                            gui->dummy(ImVec2(gui->content_avail().x, SCALE(24)));
                            ImRect drect(GetItemRectMin(), GetItemRectMax());
                            draw->rect_filled(gui->window_drawlist(), drect.Min, drect.Max, draw->get_clr(clr->selection, 0.5f));
                            draw->text_clipped(gui->window_drawlist(), font->get(my_font, 12), drect.Min + SCALE(elements->padding.x, 0), drect.Max, draw->get_clr(clr->white), data[i].items[k].key, 0, 0, {0, 0.5});
                            draw->text_clipped(gui->window_drawlist(), font->get(my_font, 12), drect.Min, drect.Max - SCALE(elements->padding.x, 0), draw->get_clr(clr->white), data[i].items[k].value, 0, 0, {1, 0.5});
                        }
                    }
                    gui->end_content();
                }
            }
            else
            {
                widgets->text(description, font->get(my_font, 12), clr->text_inactive);
                gui->dummy(SCALE(1, 1));
                widgets->text(share_code, font->get(my_font, 12), clr->text_inactive);
                widgets->text(date, font->get(my_font, 12), clr->text_inactive);

                float width = (gui->content_avail().x - SCALE(elements->padding.x * 2)) / 3;
                float height = SCALE(45);

                {
                    gui->dummy(ImVec2(width, height));
                    ImRect item_rect(GetItemRectMin(), GetItemRectMax());
                    draw->rect_filled(gui->window_drawlist(), item_rect.Min, item_rect.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding));
                    char likes_str[32];
                    snprintf(likes_str, sizeof(likes_str), "%d", likes);
                    draw->text_clipped(gui->window_drawlist(), font->get(my_font, 12), item_rect.Min, item_rect.Max, draw->get_clr(clr->white), likes_str, 0, 0, {0.5, 0.25});
                    draw->text_clipped(gui->window_drawlist(), font->get(my_font, 12), item_rect.Min, item_rect.Max, draw->get_clr(clr->text_inactive), "Likes", 0, 0, {0.5, 0.75});
                }

                gui->sameline();

                {
                    gui->dummy(ImVec2(width, height));
                    ImRect item_rect(GetItemRectMin(), GetItemRectMax());
                    draw->rect_filled(gui->window_drawlist(), item_rect.Min, item_rect.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding));
                    char dislikes_str[32];
                    snprintf(dislikes_str, sizeof(dislikes_str), "%d", dislikes);
                    draw->text_clipped(gui->window_drawlist(), font->get(my_font, 12), item_rect.Min, item_rect.Max, draw->get_clr(clr->white), dislikes_str, 0, 0, {0.5, 0.25});
                    draw->text_clipped(gui->window_drawlist(), font->get(my_font, 12), item_rect.Min, item_rect.Max, draw->get_clr(clr->text_inactive), "Dislikes", 0, 0, {0.5, 0.75});
                }

                gui->sameline();

                {
                    gui->dummy(ImVec2(width, height));
                    ImRect item_rect(GetItemRectMin(), GetItemRectMax());
                    draw->rect_filled(gui->window_drawlist(), item_rect.Min, item_rect.Max, draw->get_clr(clr->selection), SCALE(elements->child.rounding));
                    char downloads_str[32];
                    snprintf(downloads_str, sizeof(downloads_str), "%d", downloads);
                    draw->text_clipped(gui->window_drawlist(), font->get(my_font, 12), item_rect.Min, item_rect.Max, draw->get_clr(clr->white), downloads_str, 0, 0, {0.5, 0.25});
                    draw->text_clipped(gui->window_drawlist(), font->get(my_font, 12), item_rect.Min, item_rect.Max, draw->get_clr(clr->text_inactive), "Downloads", 0, 0, {0.5, 0.75});
                }
            }
        }
        gui->end_content();

        widgets->end_popup();

    }

    gui->pop_var(2);

    // if (like.Contains(GetMousePos()) && gui->is_item_hovered(0) && gui->mouse_clicked(0))
    //{
    //    config_data.is_like_pressed = true;
    //}

    // return config_data;
    // IS EXAMPLE FOR PARSING PRESSED BUTTONS

    return pressed;
}

bool c_widgets::config_manager()
{
    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems) return false;

    static std::vector<ConfigInfo> cachedConfigs;
    static bool isOpen = false;
    static char searchBuffer[128] = "";
    static bool searchClicked = false;

    // Détecter l'ouverture de l'interface
    bool currentlyOpen = true; // ou la condition qui détermine si l'interface est ouverte
    if (currentlyOpen && !isOpen) {
        // L'interface vient d'être ouverte
        needsRefresh = true;
    }
    isOpen = currentlyOpen;

    if (widgets->config_text_field_search_2("Search", searchBuffer, sizeof(searchBuffer), &searchClicked)) {
    }

    gui->sameline();

    if (widgets->fullButton("Create")) {
        widgets->open_popup("create_config_popup");
    }

    ImVec2 popup_size = SCALE(400, 300);
    ImVec2 center_pos = ImVec2(
        window->Pos.x + (window->Size.x - popup_size.x) * 0.5f,
        window->Pos.y + window->Size.y * 0.5f - SCALE(150)
    );

    static bool wasPopupOpen = false;
    bool isPopupOpen = widgets->popup2("create_config_popup", center_pos, popup_size, SCALE(elements->child.rounding), false, true);

    widgets->modal_open = isPopupOpen;

    // Bloquer les inputs quand la popup s'ouvre
    if (isPopupOpen && !wasPopupOpen) {
        InputTask_SetBlockGameInputs(true);
    }
    // Débloquer les inputs quand la popup se ferme
    else if (!isPopupOpen && wasPopupOpen) {
        InputTask_SetBlockGameInputs(false);
    }
    wasPopupOpen = isPopupOpen;

    if (isPopupOpen) {
        static char newConfigName[128] = "";
        static char newConfigDesc[256] = "";

        if (!window || window->SkipItems) {
            widgets->end_popup();
            return false;
        }

        ImVec2 window_pos = gui->window_pos();
        ImVec2 window_size = gui->window_size();
        ImDrawList* drawlist = gui->window_drawlist();

        ImVec2 titlebar_height = SCALE(0, elements->titlebar.size.y);
        ImRect titlebar_rect(window_pos, ImVec2(window_pos.x + window_size.x, window_pos.y + titlebar_height.y));

        draw->rect_filled(drawlist, titlebar_rect.Min, titlebar_rect.Max, draw->get_clr(clr->child),
                          SCALE(elements->window.rounding), draw_flags_round_corners_top);

        draw->text_clipped(drawlist, font->get(icon_font, 10),
                           titlebar_rect.Min + SCALE(elements->padding.x, 0), titlebar_rect.Max,
                           draw->get_clr(clr->accent), Strings::iconText(), nullptr, nullptr, {0, 0.5});

        draw->text_clipped(drawlist, font->get(my_font, 12),
                           titlebar_rect.Min + SCALE(elements->padding.x * 3, 0), titlebar_rect.Max,
                           draw->get_clr(clr->accent), Strings::createConfigText(), nullptr, nullptr, {0, 0.5});

        gui->dummy(titlebar_height);
        gui->dummy(SCALE(0, 15));

        ImVec2 label_size = gui->text_size(font->get(my_font, 12), Strings::lblConfigName());
        float label_offset = (popup_size.x - label_size.x) * 0.5f;
        ImGui::SetCursorPosX(label_offset);
        widgets->text(Strings::lblConfigName(), font->get(my_font, 12), clr->text_inactive);

        float field_width = SCALE(250);
        float field_offset = (popup_size.x - field_width) * 0.5f;
        ImGui::SetCursorPosX(field_offset);
        if (widgets->config_text_field(Strings::lblName(), newConfigName, sizeof(newConfigName))) {}

        ImVec2 desc_label_size = gui->text_size(font->get(my_font, 12), Strings::lblDescOptional());
        float desc_label_offset = (popup_size.x - desc_label_size.x) * 0.5f;
        ImGui::SetCursorPosX(desc_label_offset);
        widgets->text(Strings::lblDescOptional(), font->get(my_font, 12), clr->text_inactive);

        ImGui::SetCursorPosX(field_offset);
        if (widgets->config_text_field(Strings::lblDescription(), newConfigDesc, sizeof(newConfigDesc))) {}

        // Re-assert input blocking — config_text_field toggles it off when deactivated,
        // but we want inputs blocked the entire time the popup is open
        InputTask_SetBlockGameInputs(true);

        float buttons_width = SCALE(150);
        float buttons_offset = (popup_size.x - buttons_width) * 0.5f;
        ImGui::SetCursorPosX(buttons_offset);

        if (widgets->button(Strings::btnCreate())) {
            if (strlen(newConfigName) > 0 && !s_workerBusy.load()) {
                s_workerBusy.store(true);
                s_action = ACTION_SAVE;
                std::string name = newConfigName;
                std::string desc = newConfigDesc;
                std::thread([name, desc]() {
                    ConfigManager::getInstance().saveConfig(name.c_str(), desc.c_str(), "User");
                    s_workerDone.store(true);
                    s_workerBusy.store(false);
                }).detach();
                widgets->close_popup("create_config_popup");

                memset(newConfigName, 0, sizeof(newConfigName));
                memset(newConfigDesc, 0, sizeof(newConfigDesc));
            }
        }

        gui->sameline();

        if (widgets->button(Strings::btnCancel())) {
            widgets->close_popup("create_config_popup");
            memset(newConfigName, 0, sizeof(newConfigName));
            memset(newConfigDesc, 0, sizeof(newConfigDesc));
        }

        gui->dummy(SCALE(0, 20));
        widgets->end_popup();
    }

    // Récupérer le résultat du worker quand il a fini
    if (s_workerDone.load()) {
        if (s_action == ACTION_LIST) {
            cachedConfigs = std::move(s_listResult);
            // ZERO memory footprint: ConfigManager ne stocke plus l'ID, isLoaded est déjà false côté serveur
        } else {
            // save/load/delete/modify terminé — rafraîchir la liste
            needsRefresh = true;
        }
        s_action = ACTION_NONE;
        s_workerDone.store(false);
    }

    // Lancer le chargement de la liste sur un thread (non-bloquant)
    if (needsRefresh && !s_workerBusy.load()) {
        s_workerBusy.store(true);
        s_action = ACTION_LIST;
        std::thread([]() {
            s_listResult = ConfigManager::getInstance().getAvailableConfigs();
            s_workerDone.store(true);
            s_workerBusy.store(false);
        }).detach();
        needsRefresh = false;
    }

    // Lowercase search term for case-insensitive comparison
    char searchTermLower[128];
    strncpy_s(searchTermLower, sizeof(searchTermLower), searchBuffer, _TRUNCATE);
    for (char* p = searchTermLower; *p; ++p) *p = tolower(*p);
    bool hasSearchTerm = searchTermLower[0] != '\0';

    for (int i = 0; i < cachedConfigs.size(); ++i) {
        ConfigInfo& configInfo = cachedConfigs[i];

        if (hasSearchTerm) {
            char configNameLower[256];
            strncpy_s(configNameLower, sizeof(configNameLower), configInfo.name ? configInfo.name : "", _TRUNCATE);
            for (char* p = configNameLower; *p; ++p) *p = tolower(*p);
            if (strstr(configNameLower, searchTermLower) == nullptr) {
                continue;
            }
        }

        bool wasLoaded = configInfo.isLoaded;
        bool isLoaded = configInfo.isLoaded;

        bool configPressed = widgets->config(configInfo.id.c_str(), configInfo.name ? configInfo.name : "", configInfo.description ? configInfo.description : "", &isLoaded);

        // Si l'état a changé (une config a été chargée)
        if (isLoaded && !wasLoaded) {
            // Désactiver toutes les autres configs
            for (auto& cfg : cachedConfigs) {
                if (cfg.id != configInfo.id) {
                    cfg.isLoaded = false;
                }
            }
            configInfo.isLoaded = true;
        }
        else if (!isLoaded && wasLoaded) {
            configInfo.isLoaded = false;
        }
    }

    return false;
}

bool c_widgets::button(const char* name) {
    ImGuiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    const ImGuiID id = window->GetID(name);
    ImVec2 size = SCALE(75, 30);
    const ImRect rect(window->DC.CursorPos, window->DC.CursorPos + size);
    gui->item_size(rect);
    if (!gui->item_add(rect, id))
        return false;

    bool hovered, held;
    bool pressed = gui->button_behavior(rect, id, &hovered, &held);

    draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->child), SCALE(elements->child.rounding));
    draw->text_clipped(window->DrawList, font->get(my_font, 11), rect.Min, rect.Max, draw->get_clr(clr->white), name, 0, 0, {0.5, 0.5});

    return pressed;
}

bool c_widgets::button2(const char* name) {
    struct button_state
    {
        ImVec4 background, text;
    };

    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems)
    {
        return false;
    }

    ImGuiContext& g = *GImGui;
    ImGuiIO& io = g.IO;

    const ImGuiID id = window->GetID(name);
    button_state* state = gui->anim_container<button_state>(id);

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(gui->content_avail().x, SCALE(elements->checkbox.size));
    ImRect total(pos, pos + size);
    ImRect rect(total.Min + SCALE(elements->padding), total.Max - SCALE(elements->padding));

    // Calculer la taille du texte pour le bouton avec padding suffisant
    const ImVec2 label_size = ImGui::CalcTextSize(name, NULL, true);
    float button_width = label_size.x + SCALE(elements->padding.x * 2.5); // Plus de padding

    // Bouton centré verticalement avec hauteur 1.1x (au lieu de 1.5x du keybind)
    float buttonHeight = SCALE(elements->checkbox.button.y * 1.5);
    ImRect button(
        ImVec2(rect.Max.x - button_width, rect.GetCenter().y - buttonHeight / 2.0f),
        ImVec2(rect.Max.x, rect.GetCenter().y + buttonHeight / 2.0f)
    );

    gui->item_size(total);
    if (!gui->item_add(total, id))
        return false;

    bool hovered = ImGui::ItemHoverable(button, id, NULL);
    bool pressed = hovered && io.MouseClicked[0];

    // Animation colors (même style que keybind)
    ImVec4 bg_color =
        ImGui::ColorConvertU32ToFloat4(draw->get_clr(clr->selection));

    ImVec4 text_color =
        ImGui::ColorConvertU32ToFloat4(draw->get_clr(clr->white));

    // Animate colors (même vitesse que keybind)
    state->background = bg_color;
    state->text = text_color;

    // Texte à gauche - s'arrête avant le bouton avec plus d'espace
    draw->text_clipped(window->DrawList, font->get(my_font, 12),
                      total.Min + SCALE(elements->padding.x, 0),
                      ImVec2(button.Min.x - SCALE(elements->padding.x * 2), total.Max.y),
                      draw->get_clr(clr->white),
                      name, 0, 0, {0, 0.5});

    // Bouton à droite avec background (même style que keybind)
    draw->rect_filled(window->DrawList, button.Min, button.Max,
                     ImGui::ColorConvertFloat4ToU32(state->background),
                     SCALE(elements->dropdown.rounding));

    // Texte dans le bouton
    draw->text_clipped(window->DrawList, font->get(my_font, 11),
                      button.Min,
                      button.Max,
                      ImGui::ColorConvertFloat4ToU32(state->text),
                      name, 0, 0, {0.5f, 0.5f});

    // Ligne de séparation en bas
    if (gui->content_avail().y + gui->get_window()->Scroll.y > 0)
    {
        draw->line(window->DrawList, total.GetBL(), total.GetBR(), draw->get_clr(clr->selection));
    }

    return pressed;
}

bool c_widgets::button3(const char* name, const char* text) {
    struct button_state
    {
        ImVec4 background, text_color;
    };

    ImGuiWindow* window = gui->get_window();
    if (window->SkipItems)
    {
        return false;
    }

    ImGuiContext& g = *GImGui;
    ImGuiIO& io = g.IO;

    const ImGuiID id = window->GetID(name);
    button_state* state = gui->anim_container<button_state>(id);

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(gui->content_avail().x, SCALE(elements->checkbox.size));
    ImRect total(pos, pos + size);
    ImRect rect(total.Min + SCALE(elements->padding), total.Max - SCALE(elements->padding));

    // Calculer la taille du texte pour le bouton avec padding suffisant
    const ImVec2 label_size = ImGui::CalcTextSize(name, NULL, true);
    float button_width = label_size.x + SCALE(elements->padding.x * 2.5); // Plus de padding

    // Bouton centré verticalement avec hauteur 1.1x (au lieu de 1.5x du keybind)
    float buttonHeight = SCALE(elements->checkbox.button.y * 1.5);
    ImRect button(
        ImVec2(rect.Max.x - button_width, rect.GetCenter().y - buttonHeight / 2.0f),
        ImVec2(rect.Max.x, rect.GetCenter().y + buttonHeight / 2.0f)
    );

    gui->item_size(total);
    if (!gui->item_add(total, id))
        return false;

    bool hovered = ImGui::ItemHoverable(button, id, NULL);
    bool pressed = hovered && io.MouseClicked[0];

    // Animation colors (même style que keybind)
    ImVec4 bg_color =
        ImGui::ColorConvertU32ToFloat4(draw->get_clr(clr->selection));

    ImVec4 text_clr =
        ImGui::ColorConvertU32ToFloat4(draw->get_clr(clr->white));

    // Animate colors (même vitesse que keybind)
    state->background = bg_color;
    state->text_color = text_clr;

    // Texte à gauche - s'arrête avant le bouton avec plus d'espace
    draw->text_clipped(window->DrawList, font->get(my_font, 12),
                      total.Min + SCALE(elements->padding.x, 0),
                      ImVec2(button.Min.x - SCALE(elements->padding.x * 2), total.Max.y),
                      draw->get_clr(clr->white),
                      text, 0, 0, {0, 0.5});

    // Bouton à droite avec background (même style que keybind)
    draw->rect_filled(window->DrawList, button.Min, button.Max,
                     ImGui::ColorConvertFloat4ToU32(state->background),
                     SCALE(elements->dropdown.rounding));

    // Texte dans le bouton
    draw->text_clipped(window->DrawList, font->get(my_font, 11),
                      button.Min,
                      button.Max,
                      ImGui::ColorConvertFloat4ToU32(state->text_color),
                      name, 0, 0, {0.5f, 0.5f});

    // Ligne de séparation en bas
    if (gui->content_avail().y + gui->get_window()->Scroll.y > 0)
    {
        draw->line(window->DrawList, total.GetBL(), total.GetBR(), draw->get_clr(clr->selection));
    }

    return pressed;
}

bool c_widgets::fullButton(const char* name) {
    ImGuiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    const ImGuiID id = window->GetID(name);
    ImVec2 size = SCALE(0, 0);
    if (GetScrollMaxY() > 0.0f) {
        size = SCALE(64.5, 30);
    } else {
        size = SCALE(80, 30);
    }
    const ImRect rect(window->DC.CursorPos, window->DC.CursorPos + size);
    gui->item_size(rect);
    if (!gui->item_add(rect, id))
        return false;

    bool hovered, held;
    bool pressed = gui->button_behavior(rect, id, &hovered, &held);

    draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->child), SCALE(elements->child.rounding));
    draw->text_clipped(window->DrawList, font->get(my_font, 11), rect.Min, rect.Max, draw->get_clr(clr->white), name, 0, 0, {0.5, 0.5});

    return pressed;
}