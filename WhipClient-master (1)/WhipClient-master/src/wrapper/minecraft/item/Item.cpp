#include "../../../../includes/wrapper/minecraft/item/Item.h"

jclass Item::itemSwordClass = NULL;
jclass Item::itemBowClass = NULL;
jclass Item::itemPotionClass = NULL;
jclass Item::itemFoodClass = NULL;
jclass Item::itemAxeClass = NULL;
jclass Item::itemSoupClass = NULL;
jclass Item::itemBlockClass = NULL;
jclass Item::itemArmorClass = NULL;
jclass Item::itemRodClass = NULL;
jclass Item::itemPearlClass = NULL;
bool Item::selectedWeapons[3] = { false, false, false };
jclass Item::itemBaseClass = nullptr;
jmethodID Item::getIdFromItemId = nullptr;
jmethodID Item::getUnlocalizedNameId = nullptr;
