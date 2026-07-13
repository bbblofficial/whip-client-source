#pragma once

#include <vector>
#include <string>
#include <atomic>
#include <mutex>
#include <windows.h>
#include "../util/whipJson.h"
#include "../handler/SettingsHandler.h"

inline char* secureStrAlloc(const char* src) {
    if (!src || !*src) return nullptr;
    std::size_t len = std::strlen(src);
    char* buf = new char[len + 1];
    std::memcpy(buf, src, len + 1);
    return buf;
}

inline void secureStrFree(char*& ptr) {
    if (ptr) {
        SecureZeroMemory(ptr, std::strlen(ptr));
        delete[] ptr;
        ptr = nullptr;
    }
}

inline void secureStrSet(char*& dst, const char* src) {
    secureStrFree(dst);
    dst = secureStrAlloc(src);
}

inline void secureErase(std::string& s) {
    if (s.capacity() > 0) {
        SecureZeroMemory(s.data(), s.capacity());
    }
    s.clear();
}

struct ConfigMetadata {
    std::string id;
    char* name = nullptr;
    char* description = nullptr;
    std::string author;
    std::string version;
    std::string created;
    std::string modified;

    ~ConfigMetadata() {
        secureErase(id);
        secureStrFree(name);
        secureStrFree(description);
        secureErase(author);
        secureErase(version);
        secureErase(created);
        secureErase(modified);
    }

    ConfigMetadata() = default;
    ConfigMetadata(const ConfigMetadata&) = delete;
    ConfigMetadata& operator=(const ConfigMetadata&) = delete;
    ConfigMetadata(ConfigMetadata&& o) noexcept
        : id(std::move(o.id)), name(o.name), description(o.description),
          author(std::move(o.author)), version(std::move(o.version)),
          created(std::move(o.created)), modified(std::move(o.modified)) {
        o.name = nullptr; o.description = nullptr;
    }
};

struct ConfigInfo {
    std::string id;
    char* name = nullptr;
    char* description = nullptr;
    std::string author;
    std::string createdDate;
    bool isLoaded = false;

    ~ConfigInfo() {
        secureErase(id);
        secureStrFree(name);
        secureStrFree(description);
        secureErase(author);
        secureErase(createdDate);
    }

    ConfigInfo() = default;
    ConfigInfo(const ConfigInfo&) = delete;
    ConfigInfo& operator=(const ConfigInfo&) = delete;
    ConfigInfo(ConfigInfo&& o) noexcept
        : id(std::move(o.id)), name(o.name), description(o.description),
          author(std::move(o.author)), createdDate(std::move(o.createdDate)),
          isLoaded(o.isLoaded) {
        o.name = nullptr; o.description = nullptr;
    }
    ConfigInfo& operator=(ConfigInfo&& o) noexcept {
        if (this != &o) {
            secureErase(id);
            secureStrFree(name); secureStrFree(description);
            secureErase(author);
            secureErase(createdDate);
            id = std::move(o.id); name = o.name; description = o.description;
            author = std::move(o.author); createdDate = std::move(o.createdDate);
            isLoaded = o.isLoaded;
            o.name = nullptr; o.description = nullptr;
        }
        return *this;
    }
};

class ConfigManager {
public:
    ConfigManager() = default;
    ~ConfigManager() = default;

    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    void initializeConfigClient();

    bool isLoadingConfig() const {
        return m_isLoadingConfig.load();
    }

    bool saveConfig(const char* configName, const char* description = "", const char* author = "");
    bool loadConfig(const std::string& configId);
    bool deleteConfig(const std::string& configId);
    bool renameConfig(const std::string& configId, const std::string& newName);
    bool modifyConfig(const std::string& configId);

    std::vector<ConfigInfo> getAvailableConfigs() const;
    ConfigInfo* getCurrentConfig();
    bool isConfigLoaded(const std::string& configId) const;

    void clearCache();
    void secureCleanup();
    void unloadCurrentConfig();
    bool isConfigCached(const std::string& configId) const;

    static ConfigManager& getInstance();

private:

    DynamicTrackedString generateUUID() const;

    whip::WhipJsonValue serializeModuleSettings(IModule* module);
    void deserializeModuleSettings(IModule* module, const whip::WhipJsonValue& moduleJson);

    whip::WhipJsonValue createConfigJson(const ConfigMetadata& metadata);
    bool validateConfigJson(const whip::WhipJsonValue& configJson) const;
    DynamicTrackedString getCurrentTimeString() const;

    std::string m_currentConfigId;
    std::atomic<bool> m_isLoadingConfig{false};
    mutable std::mutex m_loadingMutex;

    bool m_autoSaveEnabled = false;
    int m_autoSaveInterval = 30;
};
