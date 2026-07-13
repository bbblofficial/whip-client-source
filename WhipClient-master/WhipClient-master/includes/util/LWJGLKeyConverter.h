#pragma once
#include <Windows.h>
#include <unordered_map>

class LWJGLKeyConverter {
public:
    static int lwjglToVK(int lwjglKey) {

        if (lwjglKey < 0) {
            switch (lwjglKey) {
                case -100: return VK_LBUTTON;
                case -99:  return VK_RBUTTON;
                case -98:  return VK_MBUTTON;
                case -97:  return VK_XBUTTON1;
                case -96:  return VK_XBUTTON2;
                default:   return 0;
            }
        }

        static const std::unordered_map<int, int> lwjglToVkMap = {

            {0, 0},
            {1, VK_ESCAPE},
            {14, VK_BACK},
            {15, VK_TAB},
            {28, VK_RETURN},
            {29, VK_CONTROL},
            {42, VK_SHIFT},
            {54, VK_SHIFT},
            {56, VK_MENU},
            {57, VK_SPACE},
            {58, VK_CAPITAL},
            {157, VK_CONTROL},
            {184, VK_MENU},

            {59, VK_F1},
            {60, VK_F2},
            {61, VK_F3},
            {62, VK_F4},
            {63, VK_F5},
            {64, VK_F6},
            {65, VK_F7},
            {66, VK_F8},
            {67, VK_F9},
            {68, VK_F10},
            {87, VK_F11},
            {88, VK_F12},

            {2, '1'},
            {3, '2'},
            {4, '3'},
            {5, '4'},
            {6, '5'},
            {7, '6'},
            {8, '7'},
            {9, '8'},
            {10, '9'},
            {11, '0'},

            {16, 'Q'},
            {17, 'W'},
            {18, 'E'},
            {19, 'R'},
            {20, 'T'},
            {21, 'Y'},
            {22, 'U'},
            {23, 'I'},
            {24, 'O'},
            {25, 'P'},
            {30, 'A'},
            {31, 'S'},
            {32, 'D'},
            {33, 'F'},
            {34, 'G'},
            {35, 'H'},
            {36, 'J'},
            {37, 'K'},
            {38, 'L'},
            {44, 'Z'},
            {45, 'X'},
            {46, 'C'},
            {47, 'V'},
            {48, 'B'},
            {49, 'N'},
            {50, 'M'},

            {12, VK_OEM_MINUS},
            {13, VK_OEM_PLUS},
            {26, VK_OEM_4},
            {27, VK_OEM_6},
            {39, VK_OEM_1},
            {40, VK_OEM_7},
            {41, VK_OEM_3},
            {43, VK_OEM_5},
            {51, VK_OEM_COMMA},
            {52, VK_OEM_PERIOD},
            {53, VK_OEM_2},

            {71, VK_NUMPAD7},
            {72, VK_NUMPAD8},
            {73, VK_NUMPAD9},
            {74, VK_SUBTRACT},
            {75, VK_NUMPAD4},
            {76, VK_NUMPAD5},
            {77, VK_NUMPAD6},
            {78, VK_ADD},
            {79, VK_NUMPAD1},
            {80, VK_NUMPAD2},
            {81, VK_NUMPAD3},
            {82, VK_NUMPAD0},
            {83, VK_DECIMAL},

            {199, VK_HOME},
            {200, VK_UP},
            {201, VK_PRIOR},
            {203, VK_LEFT},
            {205, VK_RIGHT},
            {207, VK_END},
            {208, VK_DOWN},
            {209, VK_NEXT},
            {210, VK_INSERT},
            {211, VK_DELETE},

            {69, VK_NUMLOCK},
            {70, VK_SCROLL},
            {156, VK_RETURN},
            {181, VK_DIVIDE},
            {183, VK_SNAPSHOT},
            {197, VK_PAUSE},
        };

        auto it = lwjglToVkMap.find(lwjglKey);
        if (it != lwjglToVkMap.end()) {
            return it->second;
        }

        return 0;
    }

    static int vkToLWJGL(int vkKey) {
        static std::unordered_map<int, int> vkToLwjglMap;

        if (vkToLwjglMap.empty()) {

            static const std::unordered_map<int, int> lwjglToVkMap = {
                {1, VK_ESCAPE}, {14, VK_BACK}, {15, VK_TAB}, {28, VK_RETURN},
                {29, VK_CONTROL}, {42, VK_SHIFT}, {56, VK_MENU}, {57, VK_SPACE},
                {59, VK_F1}, {60, VK_F2}, {61, VK_F3}, {62, VK_F4},
                {63, VK_F5}, {64, VK_F6}, {65, VK_F7}, {66, VK_F8},
                {67, VK_F9}, {68, VK_F10}, {87, VK_F11}, {88, VK_F12},
                {2, '1'}, {3, '2'}, {4, '3'}, {5, '4'}, {6, '5'},
                {7, '6'}, {8, '7'}, {9, '8'}, {10, '9'}, {11, '0'},
                {16, 'Q'}, {17, 'W'}, {18, 'E'}, {19, 'R'}, {20, 'T'},
                {21, 'Y'}, {22, 'U'}, {23, 'I'}, {24, 'O'}, {25, 'P'},
                {30, 'A'}, {31, 'S'}, {32, 'D'}, {33, 'F'}, {34, 'G'},
                {35, 'H'}, {36, 'J'}, {37, 'K'}, {38, 'L'},
                {44, 'Z'}, {45, 'X'}, {46, 'C'}, {47, 'V'}, {48, 'B'},
                {49, 'N'}, {50, 'M'},
                {200, VK_UP}, {208, VK_DOWN}, {203, VK_LEFT}, {205, VK_RIGHT},
            };

            for (const auto& [lwjgl, vk] : lwjglToVkMap) {
                vkToLwjglMap[vk] = lwjgl;
            }
        }

        auto it = vkToLwjglMap.find(vkKey);
        if (it != vkToLwjglMap.end()) {
            return it->second;
        }

        return 0;
    }
};
