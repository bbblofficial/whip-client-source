#pragma once
#include <jni.h>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

class VersionDetector {
public:
    VersionDetector() = default;
    ~VersionDetector() = default;

    static int detectCurrentVersion(JNIEnv* env);

    __forceinline static bool validateEnvironment(JNIEnv* env) {
        return env != nullptr;
    }
};

#pragma optimize("", on)
