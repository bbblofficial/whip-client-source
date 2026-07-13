#include "../../includes/event/sub/ModuleScreenDrawEvent.h"

ModuleScreenDrawEvent::ModuleScreenDrawEvent(const RECT& rect, const Gui* handler, const IModule* currentModule)
    : rect(rect), handler(handler), currentModule(currentModule) {
}

const RECT& ModuleScreenDrawEvent::getRect() const {
    return this->rect;
}

void ModuleScreenDrawEvent::setRect(const RECT& rect) {
    this->rect = rect;
}

const Gui* ModuleScreenDrawEvent::getHandler() const {
    return this->handler;
}

void ModuleScreenDrawEvent::setHandler(const Gui* handler) {
    this->handler = handler;
}

const IModule* ModuleScreenDrawEvent::getCurrentModule() const {
    return this->currentModule;
}

void ModuleScreenDrawEvent::setCurrentModule(const IModule* module) {
    this->currentModule = module;
}

std::type_index ModuleScreenDrawEvent::getType() const {
    return std::type_index(typeid(ModuleScreenDrawEvent));
}
