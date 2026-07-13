#pragma once

#include "BindBaseModule.h"
#include "../../bus/EventBus.h"
#include "../../bus/Subscriber.h"

template<typename Derived, ModuleType Type, CategoryType Category>
class ListenedBaseModule : public BindBaseModule<Derived, Type, Category> {
public:
    explicit ListenedBaseModule(const BindType bindType = BindType::TOGGLE, const int keyCode = 0)
        : BindBaseModule<Derived, Type, Category>(bindType, keyCode), eventBus(&EventBus::getInstance()) {
    }

    ~ListenedBaseModule() override {
        if (this->isEnabled()) {
            unregisterEvents();
        }
    }

    void onLoad() override {
        BindBaseModule<Derived, Type, Category>::onLoad();
    }

    void onEnable() override {
        BindBaseModule<Derived, Type, Category>::onEnable();
        registerEvents();
    }

    void onDisable() override {
        BindBaseModule<Derived, Type, Category>::onDisable();
        unregisterEvents();
    }

protected:
    EventBus* eventBus;

    template<typename EventType>
    void subscribe(std::function<void(const EventType&)> callback, const int priority = EventPriority::DEFAULT, const bool ignoreCancelled = true) {
        eventBus->subscribe<EventType>(this, std::move(callback), priority, ignoreCancelled);
    }

    virtual void registerEvents() = 0;

private:
    void unregisterEvents() {
        eventBus->unsubscribe(this);
    }
};
