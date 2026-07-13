#pragma once
#include "../../DllMain.h"

#include "HUDElementType.h"
#include "../provider/impl/HUDProvider.h"
#include "../handler/ProviderHandler.h"

#define REGISTER_HUD_ELEMENT(ClassName, HUDElementTypeEnum) \
    static ClassName g_##ClassName##_instance; \
    static bool ClassName##_hud_registered = []() { \
        auto* hudProvider = static_cast<HUDProvider*>( \
            ClientMain::getInstance().handlers.providerHandler.getProvider(ProviderType::HUD) \
        ); \
        if (hudProvider) { \
            hudProvider->registerHUDElement(HUDElementTypeEnum, &g_##ClassName##_instance); \
        } \
        return true; \
    }();
