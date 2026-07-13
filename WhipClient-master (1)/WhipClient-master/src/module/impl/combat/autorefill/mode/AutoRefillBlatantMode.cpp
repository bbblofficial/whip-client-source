#include "../../../../../../includes/module/impl/combat/autorefill/mode/AutoRefillBlatantMode.h"

void AutoRefillBlatantMode::onEnable() {

}

void AutoRefillBlatantMode::onDisable() {

}

void AutoRefillBlatantMode::performClick(
    int slot,
    int speed,
    int distance,
    Container& container,
    EntityClientPlayerMP& player,
    Minecraft& mc,
    bool dynamicSpeed,
    bool transition
    ) {
    mc.playerController().windowClick(container.windowId(), slot, 0, 1, player);
}

int AutoRefillBlatantMode::dynamicDistanceSpeed(int baseSpeed, int distance, bool active) {
    return baseSpeed;
}
