#pragma once

#include "DllMain.h"

#include "../base/BaseProvider.h"
#include "../../bus/EventBus.h"
#include "../../event/sub/Render2dEvent.h"
#include "../../hud/IHUDElement.h"
#include "../../hud/HUDElementType.h"
#include <array>

#include "hud/HUDElementRegistry.h"
#include "hud/sub/ArraylistHUDElement.h"
#include "hud/sub/NotificationHUDElement.h"
#include "wrapper/minecraft/client/minecraft.h"

class HUDProvider final : public BaseProvider<HUDProvider, ProviderType::HUD> {
    std::array<IHUDElement*, static_cast<size_t>(HUDElementType::HUD_ELEMENT_COUNT)> hudElements;

public:
    void onEnable() override {
        hudElements.fill(nullptr);

        static ArraylistHUDElement arraylistElement;
        registerHUDElement(HUDElementType::ARRAYLIST, &arraylistElement);
        static NotificationHUDElement notificationElement;
        registerHUDElement(HUDElementType::NOTIFICATION, &notificationElement);

        EventBus::getInstance().subscribe<Render2dEvent>(this, [this](const Render2dEvent& event) {
            onRender2d(event);
        });
    }

    void onDisable() override {
        EventBus::getInstance().unsubscribe(this);
    }

private:
    void onRender2d(const Render2dEvent& event) {
        renderAll(event.getEnv());
    }

public:
    void addElement(IHUDElement* element) {
        for (size_t i = 0; i < hudElements.size(); ++i) {
            if (!hudElements[i]) {
                hudElements[i] = element;
                break;
            }
        }
    }

    void registerHUDElement(HUDElementType type, IHUDElement* element) {
        const size_t index = static_cast<size_t>(type);
        if (index < hudElements.size()) {
            hudElements[index] = element;
            element->onInit();
        }
    }

    void removeElement(HUDElementType type) {
        const size_t index = static_cast<size_t>(type);
        if (index < hudElements.size()) {
            hudElements[index] = nullptr;
        }
    }

    void renderAll(JNIEnv* env) const {
        for (auto* element : hudElements) {
            if (element) {
                element->render();
            }
        }
    }

    void clear() {
        hudElements.fill(nullptr);
    }

    size_t getElementCount() const {
        size_t count = 0;
        for (const auto* element : hudElements) {
            if (element) count++;
        }
        return count;
    }

    IHUDElement* getHUDElement(HUDElementType type) const {
        const size_t index = static_cast<size_t>(type);
        if (index < hudElements.size()) {
            return hudElements[index];
        }
        return nullptr;
    }
};
