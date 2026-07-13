#include "../../includes/event/sub/DispatchKeypressesEvent.h"

OnRunTickEvent::OnRunTickEvent(JNIEnv* env)
    : EventBase(env) {

}

std::type_index OnRunTickEvent::getType() const {
    return std::type_index(typeid(OnRunTickEvent));
}
