#include "auth/version/VersionDetector.h"
#include "../../includes/DllMain.h"
#include "../../includes/handler/VersionHandler.h"

#pragma optimize("", off)

int VersionDetector::detectCurrentVersion(JNIEnv* env) {
#ifdef VMP
    VMProtectBeginUltra("detectCurrentVersion");
#endif
    if (!validateEnvironment(env)) {
        return -1;
    }

    VersionHandler* versions = &VersionHandler::getInstance();
    Version foundVersion = {};

    int result = -1;
    if (versions->findVersion(env, &foundVersion)) {
        result = foundVersion.versionKey;
    }

    return result;
#ifdef VMP
    VMProtectEnd();
#endif
}

#pragma optimize("", on)
