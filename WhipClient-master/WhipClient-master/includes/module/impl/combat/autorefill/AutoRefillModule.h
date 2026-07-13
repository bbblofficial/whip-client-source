#pragma once

#include "../../../../hud/renderer/IArraylistRenderer.h"
#include <vector>
#include <memory>
#include <utility>

#include "../../../base/DedicatedThreadBaseModule.h"
#include "../../../ModuleType.h"
#include "../../../CategoryType.h"
#include "../../../../util/JniScope.h"

#include "../../wrapper/minecraft/item/itemstack.h"
#include "../../wrapper/minecraft/entity/player/inventoryplayer.h"

#include "mode/AutoRefillMode.h"
#include "util/ClientStrings.h"
#include "event/sub/DispatchKeypressesEvent.h"
#include "event/sub/ItemUseEvent.h"

class AutoRefillModule final : public DedicatedThreadBaseModule<AutoRefillModule, ModuleType::AUTO_REFILL, CategoryType::COMBAT> {
    int mode;
    std::unique_ptr<AutoRefillMode> refillMode;
    int itemMode;
    int speed;
    bool togglerefill;
    bool randomMode;
    int lastIndex;
    std::vector<std::vector<int>> patterns;
    int currentPatternIndex;
    int lastSlotIndex;
    int slotSkipChance;

    std::vector<int> mazeGates;
    int currentGate;
    int lastGateUsed;

    bool dynamicSpeed;
    bool transition;

    bool inventoryOpened_;
    std::vector<int> potionSlots_;
    size_t currentSlotIndex_;
    bool isForwarding;
    bool isRefilling;
    bool waitingForRefill;

public:
    static bool isRefilling_() { return refilling_; }
private:
    static inline bool refilling_ = false;

    std::unordered_set<int> plannedSlots;

    enum class HealType {
        None,
        Heal,
        Soup
    };

    enum class Mode {
        BLATANT,
        LEGIT,
        SEMI_BLATANT
    };

    std::unique_ptr<AutoRefillMode> createMode(Mode mode);
    void initializeSlotPatterns();

protected:
    bool closing;

    void onUpdate(JniScope& scope) override;
    void onTick(const OnRunTickEvent& event);
    void onPostLivingUpdate(const ItemUseEvent& event);

    void registerEvents() override {
        subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
            this->onTick(event);
        }, EventPriority::DEFAULT, false);

        subscribe<ItemUseEvent>([this](const ItemUseEvent& event) {
            this->onPostLivingUpdate(event);
        }, EventPriority::DEFAULT, false);
    }

public:
    bool shouldNotify() const override { return false; }

    void onEnable() override {
        DedicatedThreadBaseModule::onEnable();
        waitingForRefill = false;
        closing = false;
        isRefilling = false;
        inventoryOpened_ = false;
        plannedSlots.clear();
        lastSlotIndex = -1;
        lastIndex = 0;
        currentPatternIndex = 0;
        currentSlotIndex_ = 0;
    }

    void onDisable() override {
        if (waitingForRefill || closing) {
            if (refillMode) refillMode->onDisable();
            waitingForRefill = false;
            closing = false;
        }
        stopDedicatedThread();
    }

    void onCleanup() override { clearInstanceBuffer(); }

    AutoRefillModule()
        : DedicatedThreadBaseModule(BindType::HOLD),
          mode(0), itemMode(0), speed(0), togglerefill(false),
          randomMode(false), lastIndex(0), currentPatternIndex(0),
          lastSlotIndex(-1), slotSkipChance(0), currentGate(0), lastGateUsed(0),
          dynamicSpeed(false), transition(true), inventoryOpened_(false),
          currentSlotIndex_(0), isForwarding(false),
          waitingForRefill(false), closing(false)
    {
        this->refillMode = createMode(Mode::BLATANT);
        initializeSlotPatterns();
    }

    void onLoad() override {
        DedicatedThreadBaseModule::onLoad();

        COMBO_SETTING_CALLBACK(mode, [this](int mode) {
            this->refillMode = createMode(static_cast<Mode>(this->mode));
        }, "Blatant", "Legit", "Semi Blatant");

        COMBO_SETTING(itemMode, Strings::itemPotion(), Strings::itemSoup(), Strings::renderBoth());
        INT_SLIDER(speed, 7, 0, 10);

        BOOL_SETTING_CONDITIONAL(randomMode, false);
        BOOL_SETTING_CONDITIONAL_OPTIONAL(dynamicSpeed, false, SETTING_VISIBILITY(mode == 1));
        BOOL_SETTING_CONDITIONAL_OPTIONAL(transition, true, SETTING_VISIBILITY(mode == 1));
    }

    int findSlot(InventoryPlayer& inventoryPlayer);
    HealType getItemHealType(ItemStack& itemStack);

    static int calculateSlotDistance(const int& slot1, const int& slot2);

private:
    mutable char instanceBuffer[64] = {};

public:
    FORMAT_FLAGS("%s %d", (this->mode == 0 ? "Blatant" : this->mode == 2 ? "Semi Blatant" : "Legit"), this->speed)
};
