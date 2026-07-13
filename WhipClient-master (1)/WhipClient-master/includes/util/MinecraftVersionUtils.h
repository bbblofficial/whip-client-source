#pragma once
#include "MinecraftDetails.h"

inline const char* minecraftVersionToString(MinecraftVersion version) {
    switch (version) {
        case MinecraftVersion::V1_7_10: return "v1_7_10";
        case MinecraftVersion::V1_8_9:  return "v1_8_9";
        default: return "unknown";
    }
}

inline const char* minecraftLauncherToString(MinecraftLauncher launcher) {
    switch (launcher) {
        case MinecraftLauncher::L_LUNAR:        return "lunar";
        case MinecraftLauncher::L_BADLION:      return "badlion";
        case MinecraftLauncher::L_CHEATBREAKER: return "cheatbreaker";
        case MinecraftLauncher::L_FORGE:        return "forge";
        case MinecraftLauncher::L_VANILLA:      return "vanilla";
        case MinecraftLauncher::L_MENORIA:      return "menoria";
        default: return "unknown";
    }
}
