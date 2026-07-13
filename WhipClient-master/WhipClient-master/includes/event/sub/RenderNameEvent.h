#ifndef RENDERNAMEEVENT_H
#define RENDERNAMEEVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include <jni.h>

#include "event/Cancellable.h"

class RenderNameEvent final : public EventBase, public Cancellable {
public:
    RenderNameEvent(JNIEnv* env);

    std::type_index getType() const override;

};

#endif
