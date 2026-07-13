#pragma once

#include <jni.h>
#include <Windows.h>
#include "HashUtils.h"
#include "util/TrackedString.h"

#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/client/session/Session.h"

#ifdef VMP
#include "VMProtectSDK.h"
#endif

static char hwid_buffer[65];

#pragma optimize("", off)
inline const char *getMinecraftPlayerInfo(JNIEnv *env) {

#ifdef VMP
    VMProtectBeginUltra("getMinecraftPlayerInfo");
#endif

    static char result[70] = {};

    if (!env) {
        return "n/a:n/a";
    }

       Minecraft theMc = Minecraft::getMinecraft(env);
       if (theMc.isNull()) {
          return "n/a:n/a";
       }

       Session sessionmngr = theMc.getSession();
       if (sessionmngr.isNull()) {
          return "n/a:n/a";
       }

       char username[32] = "n/a";
       char uuid[36] = "n/a";

       if (JavaString usernameStr = sessionmngr.getUsername(); !usernameStr.isNull()) {
          if (const auto jstr = static_cast<jstring>(usernameStr.getObj())) {
             if (const char *name = env->GetStringUTFChars(jstr, nullptr)) {
                strncpy(username, name, sizeof(username) - 1);
                username[sizeof(username) - 1] = '\0';
                env->ReleaseStringUTFChars(jstr, name);
             }
          }
       }

       if (JavaString uuidStr = sessionmngr.getPlayerID(); !uuidStr.isNull()) {
          if (const auto jstr = static_cast<jstring>(uuidStr.getObj())) {
             if (const char *id = env->GetStringUTFChars(jstr, nullptr)) {
                strncpy(uuid, id, sizeof(uuid) - 1);
                uuid[sizeof(uuid) - 1] = '\0';
                env->ReleaseStringUTFChars(jstr, id);
             }
          }
       }

       snprintf(result, sizeof(result), "%s:%s", username, uuid);
       return result;
#ifdef VMP
    VMProtectEnd();
#endif
}

inline DWORD volumeInfo() {
#ifdef VMP
    VMProtectBeginUltra("volumeInfo");
#endif
    DWORD hddNumber = 0;
    if (GetVolumeInformationA("C:\\", nullptr, 0, &hddNumber, nullptr, nullptr, nullptr, 0)) {
       return hddNumber;
    }
    return 0;
#ifdef VMP
    VMProtectEnd();
#endif
}

inline DWORD sysInfo() {
#ifdef VMP
    VMProtectBeginUltra("sysInfo");
#endif
    SYSTEM_INFO siSysInfo;
    GetSystemInfo(&siSysInfo);

    DWORD info1 = siSysInfo.dwOemId;
    DWORD info2 = siSysInfo.dwNumberOfProcessors;
    DWORD info3 = siSysInfo.dwProcessorType;
    DWORD info4 = (DWORD)siSysInfo.dwActiveProcessorMask;
    DWORD info5 = (DWORD)siSysInfo.wProcessorLevel;
    DWORD info6 = (DWORD)siSysInfo.wProcessorRevision;

    return (info1 ^ info2 ^ info3 ^ info4 ^ info5 ^ info6) * 123456789;
#ifdef VMP
    VMProtectEnd();
#endif
}

inline const char* getHwid() {
#ifdef VMP
    VMProtectBeginUltra("getHwid");
#endif

    DWORD hddNumber = 0;
    if (!GetVolumeInformationA("C:\\", nullptr, 0, &hddNumber, nullptr, nullptr, nullptr, 0)) {
        hddNumber = 0;
    }

    SYSTEM_INFO siSysInfo;
    GetSystemInfo(&siSysInfo);

    DWORD info1 = siSysInfo.dwOemId;
    DWORD info2 = siSysInfo.dwNumberOfProcessors;
    DWORD info3 = siSysInfo.dwProcessorType;
    DWORD info4 = (DWORD)siSysInfo.dwActiveProcessorMask;
    DWORD info5 = (DWORD)siSysInfo.wProcessorLevel;
    DWORD info6 = (DWORD)siSysInfo.wProcessorRevision;

    DWORD sysInfoResult = (info1 ^ info2 ^ info3 ^ info4 ^ info5 ^ info6) * 123456789;

    DWORD combined = hddNumber + sysInfoResult;

    char temp_buffer[32];
    wsprintfA(temp_buffer, "%lu", combined);

    picosha2::hash256_cstring(temp_buffer, hwid_buffer, sizeof(hwid_buffer));

    static bool tracked = false;
    if (!tracked) {
        TrackedStringRegistry::instance().track(hwid_buffer, sizeof(hwid_buffer));
        tracked = true;
    }

    return hwid_buffer;
#ifdef VMP
    VMProtectEnd();
#endif
}
#pragma optimize("", on)
