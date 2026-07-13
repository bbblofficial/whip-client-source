#include "../../../../includes/wrapper/minecraft/block/Block.h"

#include "wrapper/minecraft/world/World.h"

jmethodID Block::getUnlocalizedNameId = nullptr;
jmethodID Block::getCollisionBoundingBoxFromPoolId = nullptr;

AxisAlignedBB Block::getCollisionBoundingBoxFromPool(World world, int x, int y, int z) {
    if (!getCollisionBoundingBoxFromPoolId)
        getCollisionBoundingBoxFromPoolId = mappings->getMethod("Block#getCollisionBoundingBox");
    jobject obj = this->env->CallObjectMethod(this->obj, getCollisionBoundingBoxFromPoolId,
                                               world.getObj(), x, y, z);
    return {env, obj};
}
