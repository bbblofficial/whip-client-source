#pragma once

#include "../provider/IProvider.h"
#include "../provider/ProviderType.h"
#include <array>

class ProviderHandler {
public:
    ProviderHandler() = default;

    void load();
    void unload();
    void clear();

    IProvider* getProvider(ProviderType type);
    const IProvider* getProvider(ProviderType type) const;

    template<ProviderType Type>
    IProvider* getProvider() {
        return getProvider(Type);
    }

    template<ProviderType Type>
    const IProvider* getProvider() const {
        return getProvider(Type);
    }

    template<typename T, ProviderType Type>
    T* getTypedProvider() {
        return static_cast<T*>(getProvider(Type));
    }

    template<typename T, ProviderType Type>
    const T* getTypedProvider() const {
        return static_cast<const T*>(getProvider(Type));
    }

    static ProviderHandler& getInstance();

    ~ProviderHandler() = default;
    ProviderHandler(const ProviderHandler&) = delete;
    ProviderHandler& operator=(const ProviderHandler&) = delete;

private:

    std::array<IProvider*, static_cast<size_t>(ProviderType::PROVIDER_COUNT)> providers{};

    void registerProvider(IProvider* provider);

    template<typename T, ProviderType Type>
    void addProvider() {
        providers[static_cast<size_t>(Type)] = T::Get();
    }
};
