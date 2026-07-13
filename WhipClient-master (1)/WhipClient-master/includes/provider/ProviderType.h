#pragma once

enum class ProviderType {
    VISUAL,
    HUD,
    PACKET,
    GAME_STATE,

    PROVIDER_COUNT
};

inline const char* toName(ProviderType type) {
    switch (type) {
        case ProviderType::VISUAL:          return "Visual Provider";
        case ProviderType::HUD:             return "HUD Provider";
        case ProviderType::PACKET:          return "Packet";
        case ProviderType::GAME_STATE:      return "Game State";
        case ProviderType::PROVIDER_COUNT:  return "Invalid";
        default:                            return "Unknown";
    }
}
