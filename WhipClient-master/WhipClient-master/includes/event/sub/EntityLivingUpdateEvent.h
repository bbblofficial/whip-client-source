#pragma once
#ifndef ENTITYLIVINGUPDATE_EVENT_H
#define ENTITYLIVINGUPDATE_EVENT_H

#include <typeindex>
#include "../base/BaseEvent.h"
#include "event/Cancellable.h"

class EntityLivingUpdateEvent final : public EventBase, public Cancellable {
    float moveForward;
    float moveStrafe;
    bool shouldApplySlow;
    bool QuickAccel;
    bool stop;

public:
    EntityLivingUpdateEvent(JNIEnv* env, float moveForward, float moveStrafe, bool shouldApplySlow, bool QuickAccel, bool stop);

    [[nodiscard]] float getMoveForward() const;
    void setMoveForward(float value);

    [[nodiscard]] float getMoveStrafe() const;
    void setMoveStrafe(float value);

    bool getshouldApplySlow() const;
    void setshouldApplySlow(bool value);

    bool getQuickAccel() const;
    void setQuickAccel(bool value);

    void setStop(bool value);
    bool isStop() const;

    [[nodiscard]] std::type_index getType() const override;

};

#endif
