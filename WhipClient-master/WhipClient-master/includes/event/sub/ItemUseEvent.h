#pragma once
#ifndef ITEM_USE_EVENT_H
#define ITEM_USE_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include "event/Cancellable.h"

class ItemUseEvent final : public EventBase, public Cancellable{
public:
    ItemUseEvent(JNIEnv* env);

    std::type_index getType() const override;

};

#endif
