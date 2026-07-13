#include "handler/ProviderHandler.h"
#include "provider/impl/HUDProvider.h"
#include "provider/impl/PacketProvider.h"
#include "provider/impl/GameStateProvider.h"

void ProviderHandler::load() {
    addProvider<HUDProvider, ProviderType::HUD>();
    addProvider<PacketProvider, ProviderType::PACKET>();
    addProvider<GameStateProvider, ProviderType::GAME_STATE>();

    for (auto* provider : providers) {
        if (provider) {
            provider->setEnabled(true);
        }
    }
}

void ProviderHandler::unload() {

    for (auto* provider : providers) {
        if (provider) {
            provider->setEnabled(false);
        }
    }

    for (auto* provider : providers) {
        if (provider) {
            provider->onCleanup();
        }
    }

    clear();
}

void ProviderHandler::clear() {
    providers.fill(nullptr);
}

IProvider* ProviderHandler::getProvider(ProviderType type) {
    const size_t index = static_cast<size_t>(type);
    if (index >= providers.size()) {
        return nullptr;
    }
    return providers[index];
}

const IProvider* ProviderHandler::getProvider(ProviderType type) const {
    const size_t index = static_cast<size_t>(type);
    if (index >= providers.size()) {
        return nullptr;
    }
    return providers[index];
}

void ProviderHandler::registerProvider(IProvider* provider) {
    if (!provider) return;

    if (const size_t index = static_cast<size_t>(provider->getType()); index < providers.size()) {
        providers[index] = provider;
    }
}

ProviderHandler& ProviderHandler::getInstance() {
    static ProviderHandler instance;
    return instance;
}
