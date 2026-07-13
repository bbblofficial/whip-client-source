#include "../../../../includes/module/impl/movement/QuickAccel.h"

#include <widgets.h>
#include "bus/EventBus.h"
#include "handler/ModuleHandler.h"
#include <iostream>
#include <sstream>

#include "wrapper/minecraft/client/Minecraft.h"

void QuickAccelModule::registerEvents() {
    EventBus::getInstance().subscribe<EntityLivingUpdateEvent>(
        this,
        [this](const EntityLivingUpdateEvent& event) {
            this->OnEntityLivingUpdate(event);
        },
        EventPriority::HIGH,
        false
    );
}

void QuickAccelModule::OnEntityLivingUpdate(const EntityLivingUpdateEvent &event) {
    if (!this->isEnabled()) return;

    auto& mutableEvent = const_cast<EntityLivingUpdateEvent&>(event);

    Minecraft theMc = Minecraft::getMinecraft(event.getEnv());

    if (theMc.isNull()) {return;}

    EntityClientPlayerMP player = theMc.thePlayer();

    if (player.isNull()) {return;}

    if (this->disableOnSneak && player.isSneaking()) {
        return;
    }

    mutableEvent.setQuickAccel(true);
}

REGISTER_MODULE(QuickAccelModule, ModuleType::QUICK_ACCEL)
