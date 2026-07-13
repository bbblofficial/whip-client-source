#pragma once
#ifndef MODULESCREENDRAW_EVENT_H
#define MODULESCREENDRAW_EVENT_H

#include <typeindex>
#include <Windows.h>
#include "../base/BaseEvent.h"
#include "event/Cancellable.h"

class Gui;
class IModule;

class ModuleScreenDrawEvent final : public Event, public Cancellable {
    RECT rect;
    const Gui* handler;
    const IModule* currentModule;

public:
    ModuleScreenDrawEvent(const RECT& rect, const Gui* handler, const IModule* currentModule);

    const RECT& getRect() const;
    void setRect(const RECT& rect);

    const Gui* getHandler() const;
    void setHandler(const Gui* handler);

    const IModule* getCurrentModule() const;
    void setCurrentModule(const IModule* module);

    std::type_index getType() const override;

};

#endif
