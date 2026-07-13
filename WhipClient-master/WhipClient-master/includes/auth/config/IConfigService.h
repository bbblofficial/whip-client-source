#pragma once
#include "auth/ErrorCode.h"
#include <whipnexus/Types.h>
#include <whipnexus/SyscallManager.h>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

struct ServerConfigInfo {
    String id;
    String name;
    String description;
    String author;
    String createdDate;
    String modifiedDate;
};

struct ConfigList {
    ServerConfigInfo* items;
    u32 count;
    u32 capacity;

    __forceinline ConfigList() : items(nullptr), count(0), capacity(0) {}
    __forceinline ~ConfigList() {
        if (items) {
            for (u32 i = 0; i < count; ++i) items[i].~ServerConfigInfo();
            SyscallManager::GetWrappers()->HeapFree(items);
        }
    }
    __forceinline void add(const ServerConfigInfo& info) {
        if (count >= capacity) {
            u32 newCap = capacity == 0 ? 8 : capacity * 2;
            ServerConfigInfo* newItems = (ServerConfigInfo*)SyscallManager::GetWrappers()->HeapReAlloc(items, newCap * sizeof(ServerConfigInfo));
            if (newItems) {
                items = newItems;
                capacity = newCap;
            }
        }
        if (count < capacity) {
            new (&items[count]) ServerConfigInfo(info);
            ++count;
        }
    }
};

class IConfigService {
public:
    virtual ~IConfigService() = default;
    virtual VoidResult createConfig(const char* id, const char* name,
                                    const char* desc, const char* author,
                                    const char* data) = 0;
    virtual Result<String> loadConfig(const char* id) = 0;
    virtual VoidResult deleteConfig(const char* id) = 0;
    virtual VoidResult modifyConfig(const char* id, const char* data) = 0;
    virtual Result<ConfigList> listConfigs() = 0;
};

#pragma optimize("", on)
