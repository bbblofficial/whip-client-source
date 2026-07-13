#ifndef MODULEUTILS_H
#define MODULEUTILS_H
#include "wrapper/minecraft/client/entity/entityclientplayermp.h"
#include "wrapper/minecraft/entity/player/EntityPlayer.h"

inline double getDistance(EntityClientPlayerMP& thePlayer, Entity& player) {
    if (thePlayer.isNull() || player.isNull()) return 9999.0;
    double dx = thePlayer.posX() - player.posX();
    double dz = thePlayer.posZ() - player.posZ();
    return sqrt(dx * dx + dz * dz);
}

inline bool isPlayerNaked(EntityPlayer& player) {

    if (player.isNull()) return false;

    InventoryPlayer inventory = player.inventoryPlayer();
    if (inventory.isNull()) return false;

    for (int i = 0; i < 4; i++) {
        ItemStack armorItem = inventory.getArmorItem(i);
        if (!armorItem.isNull()) return false;
    }

    return true;
}

#endif
