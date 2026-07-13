#pragma once
#include "../../base/SharedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include "util/xor.h"
#include "util/ClientStrings.h"

class SprintModule final : public SharedThreadBaseModule<SprintModule, ModuleType::SPRINT, CategoryType::MOVEMENT> {
protected:
    void onUpdate(JniScope& scope) override;

public:
    SprintModule();
};
