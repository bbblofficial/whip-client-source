#pragma once

#include <typeinfo>
#include <typeindex>
#include <jni.h>

class JavaObject;

class Event {
public:
    virtual ~Event() = default;
    virtual std::type_index getType() const = 0;
};

class EventBase : public Event {
protected:
    JNIEnv* env;

public:
    EventBase(JNIEnv* environment)
        : env(environment) {}

    JNIEnv* getEnv() const { return env; }
};
