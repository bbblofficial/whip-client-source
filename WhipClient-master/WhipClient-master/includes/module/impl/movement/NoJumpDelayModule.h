#pragma once
#include "../../base/SharedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include "util/ClientStrings.h"

class NoJumpDelayModule final : public SharedThreadBaseModule<NoJumpDelayModule, ModuleType::NO_JUMP_DELAY, CategoryType::MOVEMENT> {
protected:
    void onUpdate(JniScope& scope) override;

public:
    NoJumpDelayModule();
};
