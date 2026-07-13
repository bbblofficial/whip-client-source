#include "module/impl/movement/noslow/mode/NoItemReleaseMode.h"

#include "wrapper/minecraft/client/minecraft.h"
#include "wrapper/minecraft/network/play/client/c07packetplayerdigging.h"
#include <iostream>

void NoItemReleaseMode::handlePacketSend(const AddSendQueueEvent& event, std::vector<bool> itemMode) {
    auto& mutableEvent = const_cast<AddSendQueueEvent&>(event);

    Packet packet(event.getEnv(), mutableEvent.getPacketObject());

    if (!packet.IsC07PacketPlayerDigging()) return;

    C07PacketPlayerDigging C07(event.getEnv(), packet.getObj());

    Minecraft theMc = Minecraft::getMinecraft(event.getEnv());

    EntityClientPlayerMP thePlayer = theMc.thePlayer();

    ItemStack heldItem = thePlayer.getHeldItem();

    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
        if (!C07.isReleaseUseItem()) return;
    }

    if (itemMode[0] == true) {
        if (heldItem.isSword()) {
            mutableEvent.setCancelled(true);
        }
    }
    if (itemMode[1] == true) {
        if (heldItem.isPunch()) {
            mutableEvent.setCancelled(true);
        }
    }
    if (itemMode[2] == true) {
        if (heldItem.isConsumable()) {
            mutableEvent.setCancelled(true);
        }
    }
    if (itemMode[3] == true) {
        mutableEvent.setCancelled(true);
    }
}

void NoItemReleaseMode::handleEntityLivingUpdate(
    const EntityLivingUpdateEvent& event,
    std::vector<bool> itemMode,
    float powerMultiplier
) {

}
