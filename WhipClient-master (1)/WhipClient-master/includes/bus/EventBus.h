#pragma once

#include "../event/Cancellable.h"
#include "Listener.h"
#include "Subscriber.h"
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <typeinfo>
#include <typeindex>
#include <memory>
#include <algorithm>
#include <ranges>
#include <type_traits>

class EventBus {
    std::unordered_map<std::type_index, std::vector<std::unique_ptr<BaseSubscriber>>> eventListenerMap;
    std::unordered_set<void*> subscribers;

    static void sortSubscribersByPriority(std::vector<std::unique_ptr<BaseSubscriber>>& subscribers) {
        std::ranges::sort(subscribers,
                          [](const std::unique_ptr<BaseSubscriber>& a, const std::unique_ptr<BaseSubscriber>& b) {
                              return a->getPriority() > b->getPriority();
                          });
    }

public:
    EventBus() = default;
    ~EventBus() = default;
    EventBus(const EventBus&) = delete;
    EventBus& operator=(const EventBus&) = delete;

    template<typename T>
    bool dispatch(const T& event) {
        const auto eventType = std::type_index(typeid(T));

        const auto it = eventListenerMap.find(eventType);
        if (it == eventListenerMap.end() || it->second.empty()) {
            return false;
        }

        bool result = false;

        if constexpr (std::is_base_of_v<Cancellable, T>) {
            const auto* cancellableEvent = static_cast<const Cancellable*>(&event);
            for (const auto& subscriber : it->second) {
                if (cancellableEvent->isCancelled() && !subscriber->shouldIgnoreCancelled()) {
                    continue;
                }
                subscriber->callListener(event);
                result = cancellableEvent->isCancelled();
            }
        } else {
            for (const auto& subscriber : it->second) {
                subscriber->callListener(event);
            }
        }

        return result;
    }

    template<typename T>
    void subscribe(void* parent, std::function<void(const T&)> callback,
    int priority = EventPriority::DEFAULT, bool ignoreCancelled = true) {
        const auto eventType = std::type_index(typeid(T));

        auto& subscriberList = eventListenerMap[eventType];
        for (const auto& sub : subscriberList) {
            if (sub->getParent() == parent) {
                return;
            }
        }

        if (!subscribers.contains(parent)) {
            subscribers.insert(parent);
        }

        auto listener = std::make_unique<LambdaListener<T>>(std::move(callback));
        auto subscriber = std::make_unique<Subscriber<T>>(parent, std::move(listener), priority, ignoreCancelled);

        subscriberList.push_back(std::move(subscriber));
        sortSubscribersByPriority(subscriberList);
    }

    void unsubscribe(void* parent) {
        const auto it = subscribers.find(parent);
        if (it == subscribers.end()) {
            return;
        }

        subscribers.erase(it);

        for (auto &subscriberList: eventListenerMap | std::views::values) {
            std::erase_if(subscriberList,
                          [parent](const std::unique_ptr<BaseSubscriber>& sub) {
                              return sub->getParent() == parent;
                          });
        }
    }

    void clear() {
        eventListenerMap.clear();
        subscribers.clear();
    }

    template<typename T>
    size_t getSubscriberCount() const {
        const auto eventType = std::type_index(typeid(T));
        const auto it = eventListenerMap.find(eventType);

        return (it != eventListenerMap.end()) ? it->second.size() : 0;
    }

    template<typename T>
    bool hasSubscribers() const {
        return getSubscriberCount<T>() > 0;
    }

    static EventBus& getInstance() {
        static EventBus instance;
        return instance;
    }
};
