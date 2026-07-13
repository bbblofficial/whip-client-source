#pragma once

#include "ListenedBaseModule.h"
#include "../../event/sub/UpdateEvent.h"
#include "../../util/JniScope.h"
#include "../ModuleType.h"
#include "../CategoryType.h"
#include "../../bind/BindType.h"

#include "gui/Gui.h"

template<typename Derived, ModuleType Type, CategoryType Category>
class SharedThreadBaseModule : public ListenedBaseModule<Derived, Type, Category> {
public:
    explicit SharedThreadBaseModule(const BindType bindType = BindType::TOGGLE, const int keyCode = 0)
        : ListenedBaseModule<Derived, Type, Category>(bindType, keyCode) {
    }

    ~SharedThreadBaseModule() override = default;

protected:
    virtual void onUpdate(JniScope& scope) = 0;

    void registerEvents() override {

        this->template subscribe<UpdateEvent>([this](const UpdateEvent& event) {
            if (this->isEnabled() && !Gui::getInstance().isOpen()) {
                if (JniScope localScope(false); localScope.isValid()) {
                    onUpdate(localScope);
                }
            }
        });
    }
};
