#pragma once
#include "ListenedBaseModule.h"
#include "../../event/sub/Render2dEvent.h"

template<typename Derived, ModuleType Type, CategoryType Category>
class Render2dBaseModule : public ListenedBaseModule<Derived, Type, Category> {
public:
    explicit Render2dBaseModule(const BindType bindType = BindType::TOGGLE, const int keyCode = 0)
        : ListenedBaseModule<Derived, Type, Category>(bindType, keyCode) {
    }

    ~Render2dBaseModule() override = default;

protected:
    virtual void onRender2d(const Render2dEvent& event) = 0;

private:
    void registerEvents() override {
        this->template subscribe<Render2dEvent>([this](const Render2dEvent& event) {
            onRender2d(event);
        });
    }
};
