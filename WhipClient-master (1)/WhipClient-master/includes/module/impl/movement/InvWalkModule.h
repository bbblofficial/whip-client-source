#pragma once
#include "../../base/ListenedBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "event/sub/DispatchKeypressesEvent.h"
#include "util/ClientStrings.h"

class InvWalkModule final : public ListenedBaseModule<InvWalkModule, ModuleType::INV_WALK, CategoryType::MOVEMENT> {
protected:
    void registerEvents() override {
        subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
            if (this->enable) {
                this->onTick(event);
            }
        }, EventPriority::DEFAULT, false);
    }

public:
    InvWalkModule();
    void onLoad() override;

private:
    int mode = 0;

    void onTick(const OnRunTickEvent& event);
};
