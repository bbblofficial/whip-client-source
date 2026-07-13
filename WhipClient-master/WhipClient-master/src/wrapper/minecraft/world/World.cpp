#include "../../../../includes/wrapper/minecraft/world/World.h"

jfieldID World::playerEntitiesId = NULL;
jfieldID World::loadedEntityListId = NULL;
jmethodID World::getEntitiesWithinAABBId = NULL;
jmethodID World::getEntitiesWithinAABBExcludingEntityId;
jmethodID World::getEntitiesInAABBexcludingId = NULL;
jmethodID World::getPlayerEntityByUUIDId = NULL;
jmethodID World::getBlockStateId = NULL;
jmethodID World::getWorldBorderId = NULL;
jmethodID World::getCollidingBoundingBoxesId = nullptr;
jfieldID World::loadedTileEntityListId = NULL;
jmethodID World::getChunkFromChunkCoordsId = NULL;
jmethodID World::rayTraceBlocksId = NULL;
jmethodID World::rayTraceBlocksFullId = NULL;
jmethodID World::getBlockId = NULL;
jmethodID World::isAirBlockId = NULL;
jmethodID World::isAirBlockBPId = NULL;
