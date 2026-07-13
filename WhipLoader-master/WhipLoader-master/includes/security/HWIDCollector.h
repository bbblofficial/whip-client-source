#pragma once

#include "auth/Credentials.h"

struct HWID {
    char cpuId[68];
    char boardSerial[128];
    char machineGuid[128];
    char biosSerial[128];
    char gpuId[128];
    char ramInfo[32];
    char tpmId[128];
    char hash[65];

    bool computeHash();
    bool isValid() const;
};

struct HWIDDisplayInfo {
    char gpuName[128];
    char cpuBrand[128];
    char ramHex[32];
    char boardModel[128];
    char screenInfo[128];
    char storageInfo[32];
};

class IHWIDCollector {
public:
    virtual ~IHWIDCollector() = default;
    virtual bool collect(HWID& out) = 0;
    virtual bool collectWithInfo(HWID& out, HWIDDisplayInfo& info) = 0;
};

class WindowsHWIDCollector : public IHWIDCollector {
public:
    bool collect(HWID& out) override;
    bool collectWithInfo(HWID& out, HWIDDisplayInfo& info) override;

private:
    bool collectCpuId(char* out, u32 outSize);
    bool collectBoardSerial(char* out, u32 outSize);
    bool collectMachineGuid(char* out, u32 outSize);
    bool collectBiosSerial(char* out, u32 outSize);
    bool collectGpuId(char* out, u32 outSize);
    bool collectRamInfo(char* out, u32 outSize);
    bool collectTpmId(char* out, u32 outSize);
    bool collectGpuName(char* out, u32 outSize);
    bool collectCpuBrand(char* out, u32 outSize);
    bool collectBoardModel(char* out, u32 outSize);
    bool collectScreenInfo(char* out, u32 outSize);
    bool collectStorageInfo(char* out, u32 outSize);
};

IHWIDCollector* createHWIDCollector();
