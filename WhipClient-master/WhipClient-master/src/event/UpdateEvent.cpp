#include "../../includes/event/sub/UpdateEvent.h"

std::type_index UpdateEvent::getType() const {
    return std::type_index(typeid(UpdateEvent));
}
