#pragma once
#include <functional>
#include <memory>

template<typename T>
class Listener {
public:
    virtual ~Listener() = default;

    virtual void call(const T& event) = 0;
};

template<typename T>
class LambdaListener : public Listener<T> {
private:
    std::function<void(const T&)> callback;

public:

    explicit LambdaListener(std::function<void(const T&)> cb) : callback(std::move(cb)) {}

    void call(const T& event) override {
        if (callback) {
            callback(event);
        }
    }
};
