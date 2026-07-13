#pragma once

#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../java/lang/String.h"

class ServerData : public JavaObject {
    static jfieldID serverIPId;

public:
    ServerData(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

    std::string getServerIP() {
        if (!serverIPId) serverIPId = mappings->getField("ServerData#serverIP");

        jstring js = (jstring)this->env->GetObjectField(this->obj, serverIPId);
        if (!js) return "";

        return JavaString::jstringToString(this->env, js);
    }
};
