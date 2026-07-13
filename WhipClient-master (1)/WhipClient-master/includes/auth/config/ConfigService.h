#pragma once
#include "auth/config/IConfigService.h"
#include <whipnexus/WhipNexus.h>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

class ConfigService : public IConfigService {
    WhipNexus* client_;
public:
    __forceinline explicit ConfigService(WhipNexus* client) : client_(client) {}

    __forceinline VoidResult createConfig(const char* id, const char* name,
                                          const char* desc, const char* author,
                                          const char* data) override {
        return VoidResult::err(ErrorCode::ConfigError, "Config service not implemented");
    }

    __forceinline Result<String> loadConfig(const char* id) override {
        return Result<String>::err(ErrorCode::ConfigError, "Config service not implemented");
    }

    __forceinline VoidResult deleteConfig(const char* id) override {
        return VoidResult::err(ErrorCode::ConfigError, "Config service not implemented");
    }

    __forceinline VoidResult modifyConfig(const char* id, const char* data) override {
        return VoidResult::err(ErrorCode::ConfigError, "Config service not implemented");
    }

    __forceinline Result<ConfigList> listConfigs() override {
        return Result<ConfigList>::err(ErrorCode::ConfigError, "Config service not implemented");
    }
};

#pragma optimize("", on)
