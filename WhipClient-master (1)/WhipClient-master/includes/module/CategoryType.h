#pragma once

#include "util/ClientStrings.h"

enum class CategoryType {
    COMBAT,
    VISUAL,
    MOVEMENT,
    MISC,
    NETWORK,
    CONFIG,
    SETTING,
    TEST,
    BACKEND,

    CATEGORY_COUNT
};

inline const char* toName(const CategoryType category) {
    switch (category) {
        case CategoryType::COMBAT:   return Strings::catCombat();
        case CategoryType::VISUAL:   return Strings::catVisual();
        case CategoryType::MOVEMENT: return Strings::catMovement();
        case CategoryType::MISC:     return Strings::catMisc();
        case CategoryType::NETWORK:  return Strings::catNetwork();
        case CategoryType::CONFIG:   return Strings::catConfig();
        case CategoryType::SETTING:  return Strings::catSetting();
        case CategoryType::TEST:     return Strings::catTest();
        case CategoryType::BACKEND:  return Strings::catBackend();
        default:                     return Strings::catUnknown();
    }
}
