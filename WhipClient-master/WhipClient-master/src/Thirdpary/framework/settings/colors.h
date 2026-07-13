#pragma once
#include "imgui.h"
#include <memory>

class c_colors
{
public:
    ImColor layout{ 10, 10, 12 };           // #0A0A0C - Fond très sombre
    ImColor child{ 15, 15, 18 };            // #0F0F12 - Panneaux légèrement plus clairs
    ImColor accent{ 185, 192, 255 };         // #5A6478 - Bleu-gris foncé subtil
    ImColor white{ 180, 180, 190 };         // #B4B4BE - Texte principal atténué
    ImColor black{ 0, 0, 0 };               // #000000 - Noir pur
    ImColor text_inactive{ 128, 128, 128 };    // #3C3C46 - Texte désactivé très sombre
    ImColor selection{ 20, 20, 25 };        // #141419 - Sélection très subtile
};

inline std::unique_ptr<c_colors> clr = std::make_unique<c_colors>();