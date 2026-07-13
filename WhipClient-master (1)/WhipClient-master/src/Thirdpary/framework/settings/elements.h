#pragma once
#include <string>
#include "imgui.h"

class c_elements
{
public:

    struct 
    {
        ImVec2 size{ 600, 400 };
        float rounding{ 3 };
    } window;

    struct 
    {
        ImVec2 size{ 600, 25 };
    } titlebar;

    struct 
    {
        ImVec2 size{ 160, 375 };
    } sidebar;

    struct 
    {
        ImVec2 size{ 440, 375 };
    } content;

    struct
    {
        float rounding{ 3 };
        float header{ 25 };
    } tab_section;

    struct {
        float rounding{ 3 };
        float header{ 25 };
        float width;
    } child;

    ImVec2 padding{ 10, 10 };

    struct 
    {
        float size{ 30 };
        float rounding{ 3 };
        float cirlce{ 4 };
        ImVec2 button{ 20, 12 };
    } checkbox;

    struct 
    {
        float height{ 48 };
        float line_height{ 7 };
        float rounding{ 3 }; 
        ImVec2 grab{ 9, 9 };
    } slider;

    struct 
    {
        float height{ 66 };
        float button_height{ 25 };
        float rounding{ 2 };
    } dropdown;

    struct 
    {
        float height{ 25 };
    } selectable;

    struct
	{
		float sv_height{ 80 };
		float circle_radius{ 3 };
		float rounding{ 3 };
		float header_height{ 30 };
		float circle_thikness{ 2 };
	} colorpicker;

    struct 
    {
        float size{ 50 };
    } config;
};

inline std::unique_ptr<c_elements> elements = std::make_unique<c_elements>();
