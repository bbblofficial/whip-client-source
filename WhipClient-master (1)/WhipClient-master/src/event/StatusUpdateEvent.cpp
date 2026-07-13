#include "../../includes/event/sub/StatusUpdateEvent.h"

StatusUpdateEvent::StatusUpdateEvent(JNIEnv* env, jbyte status)
    : EventBase(env), status(status) {
}

jbyte StatusUpdateEvent::getStatus() const {
    return status;
}

void StatusUpdateEvent::setStatus(jbyte newStatus) {
    status = newStatus;
}

std::type_index StatusUpdateEvent::getType() const {
    return std::type_index(typeid(StatusUpdateEvent));
}
