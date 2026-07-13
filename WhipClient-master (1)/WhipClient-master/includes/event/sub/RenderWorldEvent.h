#ifndef RENDERWORLDEVENT_H
#define RENDERWORLDEVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include <jni.h>

#include "event/Cancellable.h"

class RenderWorldEvent final : public EventBase, public Cancellable {
    int pass;
    float partialTicks;
    long finishTimeNano;

public:
    RenderWorldEvent(JNIEnv* env, const int& pass, const float& partialTicks, const long& finishTimeNano);

    int getPass() const;

    float getPartialTicks() const;

    long getFinishTimeNano() const;

    std::type_index getType() const override;

};

#endif
