#pragma once

#include <cstdio>
#include <cstring>
#include <Windows.h>

class IArraylistRenderer {
protected:
    mutable char instanceBuffer[64] = {0};
    bool showInArrayList = true;

public:
    virtual ~IArraylistRenderer() { secureBufferWipe(); }

    virtual const char* getDisplayName() const { return ""; }
    virtual const char* getDisplayFlags() const { return ""; }
    virtual bool shouldShowInArraylist() const { return showInArrayList; }
    virtual int getArraylistPriority() const { return 0; }
    virtual bool forceRender() const { return false; }
    void clearInstanceBuffer() const { secureBufferWipe(); }

    void setShowInArrayList(const bool show) { showInArrayList = show; }

private:
    void secureBufferWipe() const { SecureZeroMemory(instanceBuffer, sizeof(instanceBuffer)); }
};

#define FORMAT_FLAGS(format, ...) \
const char* getDisplayFlags() const override { \
SecureZeroMemory(instanceBuffer, sizeof(instanceBuffer)); \
snprintf(instanceBuffer, 63, format, __VA_ARGS__); \
return instanceBuffer; \
}
