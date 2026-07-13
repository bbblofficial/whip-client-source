#pragma once

#include "../event/base/BaseEvent.h"
#include <memory>

namespace EventPriority {
    constexpr int VERY_LOW = -20;
    constexpr int LOW = -10;
    constexpr int DEFAULT = 0;
    constexpr int MEDIUM = 10;
    constexpr int HIGH = 20;
}

class BaseSubscriber {
public:
    virtual ~BaseSubscriber() = default;

    virtual void callListener(const Event& event) = 0;

    virtual int getPriority() const = 0;

    virtual bool shouldIgnoreCancelled() const = 0;

    virtual void* getParent() const = 0;
};

template<typename T>
class Subscriber final : public BaseSubscriber {
    void* parent;
    std::unique_ptr<Listener<T>> listener;
    int priority;
    bool ignoreCancelled;

public:
    Subscriber(void* parent, std::unique_ptr<Listener<T>> listener, int priority, bool ignoreCancelled)
        : parent(parent), listener(std::move(listener)), priority(priority), ignoreCancelled(ignoreCancelled) {
    }

    void callListener(const Event& event) override {
        listener->call(static_cast<const T&>(event));
    }

    int getPriority() const override {
        return priority;
    }

    bool shouldIgnoreCancelled() const override {
        return ignoreCancelled;
    }

    void* getParent() const override {
        return parent;
    }
};
