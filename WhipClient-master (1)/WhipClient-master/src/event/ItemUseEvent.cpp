#include "../../includes/event/sub/ItemUseEvent.h"

ItemUseEvent::ItemUseEvent(JNIEnv* env)
    : EventBase(env) {

}

std::type_index ItemUseEvent::getType() const {
    return std::type_index(typeid(ItemUseEvent));
}
