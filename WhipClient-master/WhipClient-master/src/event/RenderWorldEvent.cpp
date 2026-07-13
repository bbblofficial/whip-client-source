#include "../../includes/event/sub/RenderWorldEvent.h"

RenderWorldEvent::RenderWorldEvent(JNIEnv* env, const int& pass, const float& partialTicks, const long& finishTimeNano)
    : EventBase(env), pass(pass), partialTicks(partialTicks), finishTimeNano(finishTimeNano) {
}

int RenderWorldEvent::getPass() const {
    return pass;
}

float RenderWorldEvent::getPartialTicks() const {
    return partialTicks;
}

long RenderWorldEvent::getFinishTimeNano() const {
    return finishTimeNano;
}

std::type_index RenderWorldEvent::getType() const {
    return std::type_index(typeid(RenderWorldEvent));
}
