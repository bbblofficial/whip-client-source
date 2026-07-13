#include "wrapper/minecraft/tileentity/TileEntity.h"

jmethodID TileEntity::getPosId = nullptr;
jmethodID TileEntity::getBlockTypeId = nullptr;
jfieldID TileEntity::GetxCoordId = nullptr;
jfieldID TileEntity::GetyCoordId = nullptr;
jfieldID TileEntity::GetzCoordId = nullptr;
