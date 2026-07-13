#include "../../../../includes/wrapper/minecraft/item/ItemStack.h"

#include "../../../../includes/wrapper/minecraft/entity/EntityLivingBase.h"
#include "../../../../includes/wrapper/minecraft/entity/player/EntityPlayer.h"
#include "wrapper/minecraft/block/block.h"

jfieldID ItemStack::theItemId = NULL;
jfieldID ItemStack::metadataId = NULL;
jfieldID ItemStack::stackSizeId = NULL;
jmethodID ItemStack::hitEntityId = NULL;
jmethodID ItemStack::canDestroyId = NULL;
jmethodID ItemStack::getStrVsBlockId = NULL;
jmethodID ItemStack::getDisplayNameId = NULL;

bool ItemStack::hitEntity(EntityLivingBase entity, EntityPlayer player) {
    if (!hitEntityId) hitEntityId = mappings->getMethod("ItemStack#hitEntity");
    return this->env->CallBooleanMethod(this->obj, hitEntityId, entity.getObj(), player.getObj());
}

bool ItemStack::canDestroy(Block block) {
    if (!canDestroyId) canDestroyId = mappings->getMethod("ItemStack#canDestroy");
    return this->env->CallBooleanMethod(this->obj, canDestroyId, block.getObj());
}
