#pragma once
#include "../../../../hud/renderer/IArraylistRenderer.h"

#include "module/base/ListenedBaseModule.h"
#include <imgui.h>
#include <memory>

#include "event/sub/EntityLivingUpdateEvent.h"
#include "mode/NoSlowMode.h"
#include "util/xor.h"
#include "util/ClientStrings.h"

class NoSlowModule final : public ListenedBaseModule<NoSlowModule, ModuleType::NO_SLOW, CategoryType::MOVEMENT> {
    static constexpr auto MODULE_COLOR = ImColor(138, 43, 226, 255);

    int mode;
    std::unique_ptr<NoSlowMode> noSlowMode;
    std::vector<bool> itemMode = {true, false, true, false};
    float swordSlow;
    float bowSlow;
    float consumableSlow;
    float allSlow;
    bool onlySprinting = false;
    bool wasSprinting_ = false;

    enum class Mode {
        NO_ITEM_RELEASE,
        NO_SLOW
    };

    std::unique_ptr<NoSlowMode> createMode(Mode mode);

protected:
    void registerEvents() override;

public:
    NoSlowModule() : mode(0), itemMode(0), swordSlow(100.0f), consumableSlow(100.0f), allSlow(100.0f) {
        this->noSlowMode = createMode(Mode::NO_ITEM_RELEASE);
    }

    ~NoSlowModule() override = default;

    void onCleanup() override {
        noSlowMode.reset();
        itemMode.clear();
        itemMode.shrink_to_fit();
        clearInstanceBuffer();
    }

    void onLoad() override {
        ListenedBaseModule::onLoad();

        itemMode = {true, false, true, false};

        COMBO_SETTING_CALLBACK(mode, [this](int mode) {
            this->noSlowMode = createMode(static_cast<Mode>(this->mode));
        }, Strings::modeNoItemRelease(), Strings::modeNoSlow());

        MULTI_COMBO_SETTING(itemMode, Strings::itemSword(), Strings::itemBow(), Strings::itemConsumable(), Strings::itemAll());
        FLOAT_SLIDER_OPTIONAL(swordSlow, 100.0f, 0.0f, 100.0f, SETTING_VISIBILITY(itemMode[0] == true && mode == 1));
        FLOAT_SLIDER_OPTIONAL(bowSlow, 100.0f, 0.0f, 100.0f, SETTING_VISIBILITY(itemMode[1] == true && mode == 1));
        FLOAT_SLIDER_OPTIONAL(consumableSlow, 100.0f, 0.0f, 100.0f, SETTING_VISIBILITY(itemMode[2] == true && mode == 1));
        FLOAT_SLIDER_OPTIONAL(allSlow, 100.0f, 0.0f, 100.0f, SETTING_VISIBILITY(itemMode[3] == true && mode == 1));
        BOOL_SETTING_CONDITIONAL(onlySprinting, false);
    }

    void onPacketSend(const AddSendQueueEvent& event);
    void OnEntityLivingUpdate(const EntityLivingUpdateEvent& event);

private:
	mutable char instanceBuffer[64] = {0};

public:

    FORMAT_FLAGS("%s", (this->mode == 0 ? Strings::modeNoItemRelease() : Strings::modeNoSlow()))
};
