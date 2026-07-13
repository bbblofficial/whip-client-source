#pragma once
#include <whipnexus/Types.h>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

struct MachineInfo {
    String hwid;
    String pcName;
    String os;
    String executablePath;
    String gpuName;
    String cpuBrand;
    String ramHex;
    String boardModel;
    String screenInfo;
    String storageInfo;
    __forceinline bool isValid() const { return hwid.length > 0; }
};

struct AuthPayload {
    MachineInfo machine;
    i64 timestamp;
    __forceinline bool isValid() const { return machine.isValid(); }
};

#pragma optimize("", on)
