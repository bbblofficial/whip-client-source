#pragma once

#include "../../base/SharedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include "../../../wrapper/minecraft/client/settings/KeyBinding.h"
#include <windows.h>

class BridgeAssistModule final : public SharedThreadBaseModule<BridgeAssistModule, ModuleType::BRIDGE_ASSIST, CategoryType::MOVEMENT> {
    int mode = 0;
    bool disableSprinting = false;

    bool isEdge_ = false;
    bool m_prev = false;
    bool hasPressedShift_ = false;
    bool isBridging_ = false;
    bool jumped_ = false;
    bool wasForwardPressed_ = false;

protected:
    void onUpdate(JniScope& scope) override;

public:
    BridgeAssistModule();

    void onLoad() override;
    void onEnable() override;
    void onDisable() override;

private:
    void sneak(KeyBinding& sneakBind);
    void unsneak(KeyBinding& sneakBind);
    void sendKey(WORD vkKey, bool down);

    mutable char instanceBuffer[64] = {0};
    void clearInstanceBuffer() const { memset(instanceBuffer, 0, sizeof(instanceBuffer)); }
};
