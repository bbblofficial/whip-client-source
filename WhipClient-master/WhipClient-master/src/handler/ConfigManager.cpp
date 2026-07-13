#include "../../includes/manager/ConfigManager.h"
#include "../../includes/handler/SettingsHandler.h"
#include "../../includes/handler/ModuleHandler.h"
#include "../../includes/module/impl/visual/NotificationModule.h"
#include "../../includes/manager/BindManager.h"
#include "../../includes/config/codec/SettingCodecRegistry.h"
#include "../../includes/config/ModuleConfigRegistry.h"
#include <ctime>
#include <cstring>
#include <random>
#include <cstdio>

#include "auth/config/IConfigService.h"
#include "auth/service/WhipAuthService.h"
#include "auth/protocol/PacketOpcodes.h"
#include "util/HWIDUtils.h"
#include "util/TrackedString.h"
#include "ClientMain.h"
#include <whipnexus/WhipNexus.h>
#include <whipnexus/BinaryWriter.h>
#include <whipnexus/BinaryReader.h>

static constexpr u16 CONFIG_REQUEST_TYPE  = WhipOpcodes::CONFIG_REQUEST;
static constexpr u16 CONFIG_RESPONSE_TYPE = WhipOpcodes::CONFIG_RESPONSE;

enum class ConfigOp : byte {
    OP_CREATE = 0x00,
    OP_GET    = 0x01,
    OP_DELETE = 0x02,
    OP_UPDATE = 0x03,
    OP_LIST   = 0x04
};

static bool sendConfigRequest(WhipAuthService* authService, ConfigOp operation,
                              const char* configId, const char* name,
                              const char* desc, const char* author,
                              const char* data, whip::WhipJsonValue* outJson = nullptr,
                              std::vector<ServerConfigInfo>* outList = nullptr) {
    auto* client = authService->getClient();
    if (!client || !authService->isAuthenticated()) {
        return false;
    }

    auto* configCtx = authService->getConfigContext();

    ResetEvent(configCtx->completedEvent);
    configCtx->received = false;
    if (configCtx->responseData) {
        SyscallManager::GetWrappers()->HeapFree(configCtx->responseData);
        configCtx->responseData = nullptr;
    }
    configCtx->responseLength = 0;

    i64 timestamp = static_cast<i64>(std::time(nullptr));

    static const u32 CONFIG_BUF_SIZE = 65536;
    // The WhipNexus event loop (startEventLoop) reads the socket on its own thread
    // WITHOUT honoring lockIO(). While it runs, CONFIG_RESPONSE is delivered to the
    // registered onConfigResponse handler (-> configCtx), so a synchronous
    // receiveDecryptedPacket() here would race/lose it. Mirror sendHeartbeat: use the
    // async completedEvent path when the loop is running, sync fallback otherwise.
    const bool eventLoopMode = client->isEventLoopRunning();

    client->lockIO();

    bool sendSuccess = false;
    {
        BinaryWriter writer(4096);

        byte opByte = static_cast<byte>(operation);
        writer.writeFixedBytes(&opByte, 1);
        writer.writeLong(timestamp);

        switch (operation) {
            case ConfigOp::OP_CREATE:
                writer.writeString(configId ? configId : "");
                writer.writeString(name ? name : "");
                writer.writeString(desc ? desc : "");
                writer.writeString(author ? author : "");
                {
                    i32 dataLen = data ? static_cast<i32>(strlen(data)) : 0;
                    writer.writeInt(dataLen);
                    if (dataLen > 0) {
                        writer.writeFixedBytes((const byte*)data, dataLen);
                    }
                }
                break;
            case ConfigOp::OP_UPDATE:
                writer.writeString(configId ? configId : "");
                {
                    i32 dataLen = data ? static_cast<i32>(strlen(data)) : 0;
                    writer.writeInt(dataLen);
                    if (dataLen > 0) {
                        writer.writeFixedBytes((const byte*)data, dataLen);
                    }
                }
                break;
            case ConfigOp::OP_GET:
            case ConfigOp::OP_DELETE:
                writer.writeString(configId ? configId : "");
                break;
            case ConfigOp::OP_LIST:
                break;
        }

        writer.writeString(authService->getPCName());
        writer.writeString(authService->getExecutablePath());

        SecureValue<32> authHmac;
        authService->computeAuthHmac(WhipOpcodes::CONFIG_REQUEST, "", timestamp, authHmac.data);
        writer.writeFixedBytes(authHmac.data, 32);

        sendSuccess = client->sendPacket(CONFIG_REQUEST_TYPE, writer.getData(), writer.getSize());

    }

    if (!sendSuccess) {
        client->unlockIO();
        return false;
    }

    // Response buffer the parse below reads from. In event-loop mode the response is
    // delivered asynchronously into configCtx by onConfigResponse; in the sync fallback
    // (pre-event-loop / auth phase) we pump the socket ourselves into respBuf.
    byte* respData = nullptr;
    u32 respLen = 0;
    byte* respBuf = nullptr;   // heap buffer owned only by the sync fallback

    if (eventLoopMode) {
        if (WaitForSingleObject(configCtx->completedEvent, 10000) != WAIT_OBJECT_0
            || !configCtx->received || !configCtx->responseData) {
            client->unlockIO();
            return false;
        }
        respData = configCtx->responseData;
        respLen = configCtx->responseLength;
    } else {
        respBuf = (byte*)SyscallManager::GetWrappers()->HeapAlloc(CONFIG_BUF_SIZE);
        if (!respBuf) {
            client->unlockIO();
            return false;
        }

        u16 respType = 0;
        bool gotResponse = false;

        for (int attempts = 0; attempts < 10; attempts++) {
            respLen = 0;
            if (!client->receiveDecryptedPacket(respType, respBuf, &respLen, CONFIG_BUF_SIZE)) {
                SecureZeroMemory(respBuf, CONFIG_BUF_SIZE);
                SyscallManager::GetWrappers()->HeapFree(respBuf);
                client->unlockIO();
                return false;
            }
            if (respType == CONFIG_RESPONSE_TYPE) {
                gotResponse = true;
                break;
            }

            client->dispatchPacket(respType, respBuf, respLen);
        }

        if (!gotResponse) {
            SecureZeroMemory(respBuf, CONFIG_BUF_SIZE);
            SyscallManager::GetWrappers()->HeapFree(respBuf);
            client->unlockIO();
            return false;
        }

        respData = respBuf;
    }

    BinaryReader reader(respData, respLen);
    bool success = reader.readBool();
    if (!success) {
        if (respBuf) {
            SecureZeroMemory(respBuf, CONFIG_BUF_SIZE);
            SyscallManager::GetWrappers()->HeapFree(respBuf);
        }
        client->unlockIO();
        return false;
    }

    byte opByte2 = 0;
    reader.readFixedBytes(&opByte2, 1);

    char msgBuf[512];
    reader.readString(msgBuf, sizeof(msgBuf));

    SecureZeroMemory(msgBuf, sizeof(msgBuf));

    i32 dataLen = reader.readInt();
    if (dataLen > 0 && operation == ConfigOp::OP_GET && outJson) {

        char* tempJsonBuf = new char[dataLen + 1];
        reader.readFixedBytes((byte*)tempJsonBuf, dataLen);
        tempJsonBuf[dataLen] = '\0';

        *outJson = whip::WhipJsonValue::parse(tempJsonBuf);

        SecureZeroMemory(tempJsonBuf, dataLen + 1);
        delete[] tempJsonBuf;
    }

    if (operation == ConfigOp::OP_LIST && outList) {
        i32 entryCount = reader.readInt();
        for (i32 i = 0; i < entryCount; i++) {
            ServerConfigInfo entry;
            char idBuf[64], nameBuf[256], descBuf[512], authorBuf[128], createdBuf[64], modifiedBuf[64];
            reader.readString(idBuf, sizeof(idBuf));
            reader.readString(nameBuf, sizeof(nameBuf));
            reader.readString(descBuf, sizeof(descBuf));
            reader.readString(authorBuf, sizeof(authorBuf));
            reader.readString(createdBuf, sizeof(createdBuf));
            reader.readString(modifiedBuf, sizeof(modifiedBuf));

            entry.id = String(idBuf);
            entry.name = String(nameBuf);
            entry.description = String(descBuf);
            entry.author = String(authorBuf);
            entry.createdDate = String(createdBuf);
            entry.modifiedDate = String(modifiedBuf);

            SecureZeroMemory(idBuf, sizeof(idBuf));
            SecureZeroMemory(nameBuf, sizeof(nameBuf));
            SecureZeroMemory(descBuf, sizeof(descBuf));
            SecureZeroMemory(authorBuf, sizeof(authorBuf));
            SecureZeroMemory(createdBuf, sizeof(createdBuf));
            SecureZeroMemory(modifiedBuf, sizeof(modifiedBuf));

            outList->push_back(entry);
        }
    }

    if (respBuf) {
        SecureZeroMemory(respBuf, CONFIG_BUF_SIZE);
        SyscallManager::GetWrappers()->HeapFree(respBuf);
    }
    client->unlockIO();
    return true;
}

class LoadingGuard {
public:
    LoadingGuard(std::atomic<bool>& flag, std::mutex& mutex)
        : m_flag(flag), m_lock(mutex) {
        m_flag.store(true);
    }

    ~LoadingGuard() {
        m_flag.store(false);
    }

private:
    std::atomic<bool>& m_flag;
    std::unique_lock<std::mutex> m_lock;
};

DynamicTrackedString ConfigManager::generateUUID() const {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;

    uint64_t part1 = dis(gen);
    uint64_t part2 = dis(gen);

    char buf[48];
    snprintf(buf, sizeof(buf), "%08llx-%04llx-%04llx-%04llx-%012llx",
        (unsigned long long)(part1 >> 32),
        (unsigned long long)((part1 >> 16) & 0xFFFF),
        (unsigned long long)(part1 & 0xFFFF),
        (unsigned long long)(part2 >> 48),
        (unsigned long long)(part2 & 0xFFFFFFFFFFFFULL));

    DynamicTrackedString result(buf);
    SecureZeroMemory(buf, sizeof(buf));
    return result;
}

void ConfigManager::initializeConfigClient() {

}

bool ConfigManager::saveConfig(const char* configName, const char* description, const char* author) {
    initializeConfigClient();

    DynamicTrackedString configId = generateUUID();

    ConfigMetadata metadata;
    metadata.id = std::string(configId.c_str());
    secureStrSet(metadata.name, configName);
    secureStrSet(metadata.description, description);
    metadata.author = author ? author : "";
    metadata.version = "2.0";
    DynamicTrackedString tempTime = getCurrentTimeString();
    metadata.created = std::string(tempTime.c_str());
    metadata.modified = std::string(tempTime.c_str());

    whip::WhipJsonValue configJson = createConfigJson(metadata);

    auto& moduleHandler = ModuleHandler::getInstance();
    auto modules = moduleHandler.getModules();

    for (auto* module : modules) {
        if (!module) continue;

        DynamicTrackedString moduleIdentifier(toName(getModuleIdentifier(module)));
        whip::WhipJsonValue moduleJson = serializeModuleSettings(module);

        if (!moduleJson.empty()) {
            configJson["modules"][moduleIdentifier.c_str()] = std::move(moduleJson);
        }
        moduleJson.clear();

    }

    DynamicTrackedString configDataStr = configJson.dumpSecure();
    DynamicTrackedString descStr(description ? description : "");
    DynamicTrackedString authorStr(author ? author : "");

    auto* authService = ClientMain::getInstance().getAuthService();
    if (!authService || !authService->getClient()) {

        return false;
    }

    bool sent = sendConfigRequest(authService, ConfigOp::OP_CREATE, configId.c_str(), configName,
                           descStr.c_str(), authorStr.c_str(), configDataStr.c_str(), nullptr);

    if (!sent) {

        auto notifModule = ModuleHandler::getInstance().getModule<ModuleType::NOTIFICATION>();
        if (notifModule && notifModule->isEnabled()) {
            static_cast<NotificationModule*>(notifModule)->addMessageNotificationForced(
                "Failed to create config on server", NotificationModule::errorColor);
        }
        return false;
    }

    configJson.clear();

    auto notificationModule = ModuleHandler::getInstance().getModule<ModuleType::NOTIFICATION>();
    if (notificationModule && notificationModule->isEnabled()) {
        std::string successMsg = std::string(configName) + Strings::msgConfigCreatedSuccess();
        static_cast<NotificationModule*>(notificationModule)->addMessageNotificationForced(
            std::move(successMsg),
            NotificationModule::successColor
        );
    }

    return true;
}

bool ConfigManager::loadConfig(const std::string& configId) {

    DynamicTrackedString localConfigId(configId.c_str());

    LoadingGuard guard(m_isLoadingConfig, m_loadingMutex);

    initializeConfigClient();

    auto notificationModule = ModuleHandler::getInstance().getModule<ModuleType::NOTIFICATION>();
    bool success = false;

    {

        auto* authService = ClientMain::getInstance().getAuthService();
        if (!authService || !authService->getClient()) {

            return false;
        }

        whip::WhipJsonValue serverJson;
        if (!sendConfigRequest(authService, ConfigOp::OP_GET, localConfigId.c_str(), nullptr, nullptr, nullptr, nullptr, &serverJson)) {
            serverJson.clear();

            return false;
        }

        try {

            if (!validateConfigJson(serverJson)) {
                serverJson.clear();

                return false;
            }

            auto& moduleHandler = ModuleHandler::getInstance();
            auto modules = moduleHandler.getModules();

            for (auto* module : modules) {
                if (!module) continue;

                DynamicTrackedString moduleIdentifier(toName(getModuleIdentifier(module)));

                if (serverJson["modules"].contains(moduleIdentifier.c_str())) {
                    deserializeModuleSettings(module, serverJson["modules"][moduleIdentifier.c_str()]);
                }

            }

            serverJson.clear();

            m_currentConfigId = std::string(localConfigId.c_str());
            success = true;
        } catch (const std::exception&) {
            serverJson.clear();

            return false;
        }
    }

    if (success && notificationModule && notificationModule->isEnabled()) {
        static_cast<NotificationModule*>(notificationModule)->addMessageNotificationForced(
            Strings::msgConfigLoadedSuccess(),
            NotificationModule::successColor
        );
    }

    return success;
}

bool ConfigManager::deleteConfig(const std::string& configId) {

    DynamicTrackedString localConfigId(configId.c_str());
    initializeConfigClient();

    DynamicTrackedString configName("Config");

    auto* authService = ClientMain::getInstance().getAuthService();
    if (authService && authService->getClient()) {
        if (!sendConfigRequest(authService, ConfigOp::OP_DELETE, localConfigId.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr)) {

            auto notifModule = ModuleHandler::getInstance().getModule<ModuleType::NOTIFICATION>();
            if (notifModule && notifModule->isEnabled()) {
                static_cast<NotificationModule*>(notifModule)->addMessageNotificationForced(
                    "Failed to delete config from server", NotificationModule::errorColor);
            }
            return false;
        }
    }

    if (m_currentConfigId == std::string(localConfigId.c_str())) {
        secureErase(m_currentConfigId);
    }

    auto notificationModule = ModuleHandler::getInstance().getModule<ModuleType::NOTIFICATION>();
    if (notificationModule && notificationModule->isEnabled()) {
        DynamicTrackedString successMsg(configName.c_str());
        successMsg = DynamicTrackedString((std::string(successMsg.c_str()) + Strings::msgConfigDeletedSuccess()).c_str());
        static_cast<NotificationModule*>(notificationModule)->addMessageNotificationForced(
            std::string(successMsg.c_str()),
            NotificationModule::successColor
        );

    }

    return true;
}

bool ConfigManager::renameConfig(const std::string& configId, const std::string& newName) {

    DynamicTrackedString localConfigId(configId.c_str());
    DynamicTrackedString newNameStr(newName.c_str());
    initializeConfigClient();

    auto* authService = ClientMain::getInstance().getAuthService();
    if (!authService || !authService->getClient()) {

        return false;
    }

    whip::WhipJsonValue updatedJson;
    if (!sendConfigRequest(authService, ConfigOp::OP_GET, localConfigId.c_str(), nullptr, nullptr, nullptr, nullptr, &updatedJson)) {
        updatedJson.clear();

        return false;
    }

    updatedJson["name"] = newNameStr.c_str();
    DynamicTrackedString tempTime = getCurrentTimeString();
    updatedJson["metadata"]["modified"] = tempTime.c_str();

    DynamicTrackedString configDataStr = updatedJson.dumpSecure();
    bool sent = sendConfigRequest(authService, ConfigOp::OP_UPDATE, localConfigId.c_str(), nullptr, nullptr, nullptr, configDataStr.c_str(), nullptr);

    updatedJson.clear();

    if (!sent) {

        return false;
    }

    return true;
}

bool ConfigManager::modifyConfig(const std::string& configId) {

    DynamicTrackedString localConfigId(configId.c_str());
    initializeConfigClient();

    auto* authService = ClientMain::getInstance().getAuthService();
    if (!authService || !authService->getClient()) {

        return false;
    }

    whip::WhipJsonValue existingJson;
    if (!sendConfigRequest(authService, ConfigOp::OP_GET, localConfigId.c_str(), nullptr, nullptr, nullptr, nullptr, &existingJson)) {
        existingJson.clear();

        return false;
    }

    DynamicTrackedString description;
    DynamicTrackedString author;
    DynamicTrackedString created;
    DynamicTrackedString name;

    if (existingJson.contains("metadata")) {
        const whip::WhipJsonValue& metadataJson = existingJson["metadata"];
        if (metadataJson.contains("description")) {
            description = metadataJson["description"].getSecureString();
        }
        if (metadataJson.contains("author")) {
            author = metadataJson["author"].getSecureString();
        }
        if (metadataJson.contains("created")) {
            created = metadataJson["created"].getSecureString();
        }
    }
    if (existingJson.contains("name")) {
        name = existingJson["name"].getSecureString();
    }

    existingJson.clear();

    ConfigMetadata metadata;
    metadata.id = std::string(localConfigId.c_str());
    secureStrSet(metadata.name, name.c_str());

    secureStrSet(metadata.description, description.c_str());

    metadata.author = std::string(author.c_str());

    metadata.version = "2.0";
    if (created.c_str() && created.c_str()[0] != '\0') {
        metadata.created = std::string(created.c_str());
    } else {
        DynamicTrackedString fallbackTime = getCurrentTimeString();
        metadata.created = std::string(fallbackTime.c_str());

    }

    DynamicTrackedString modifiedTime = getCurrentTimeString();
    metadata.modified = std::string(modifiedTime.c_str());

    whip::WhipJsonValue configJson = createConfigJson(metadata);

    auto& moduleHandler = ModuleHandler::getInstance();
    auto modules = moduleHandler.getModules();

    for (auto* module : modules) {
        if (!module) continue;

        DynamicTrackedString moduleIdentifier(toName(getModuleIdentifier(module)));
        whip::WhipJsonValue moduleJson = serializeModuleSettings(module);

        if (!moduleJson.empty()) {
            configJson["modules"][moduleIdentifier.c_str()] = std::move(moduleJson);
        }

        moduleJson.clear();

    }

    DynamicTrackedString configDataStr = configJson.dumpSecure();
    bool sent = sendConfigRequest(authService, ConfigOp::OP_UPDATE, localConfigId.c_str(), nullptr, nullptr, nullptr, configDataStr.c_str(), nullptr);

    configJson.clear();

    if (!sent) {

        auto notifModule = ModuleHandler::getInstance().getModule<ModuleType::NOTIFICATION>();
        if (notifModule && notifModule->isEnabled()) {
            static_cast<NotificationModule*>(notifModule)->addMessageNotificationForced(
                "Failed to update config on server", NotificationModule::errorColor);
        }
        return false;
    }

    auto notificationModule = ModuleHandler::getInstance().getModule<ModuleType::NOTIFICATION>();
    if (notificationModule && notificationModule->isEnabled()) {
        std::string successMsg = std::string(metadata.name ? metadata.name : "") + Strings::msgConfigModifiedSuccess();
        static_cast<NotificationModule*>(notificationModule)->addMessageNotificationForced(
            std::move(successMsg),
            NotificationModule::successColor
        );
    }

    return true;
}

std::vector<ConfigInfo> ConfigManager::getAvailableConfigs() const {
    std::vector<ConfigInfo> configs;

    auto* authService = ClientMain::getInstance().getAuthService();
    if (authService && authService->getClient()) {
        std::vector<ServerConfigInfo> serverConfigs;
        if (sendConfigRequest(authService, ConfigOp::OP_LIST, "", nullptr, nullptr, nullptr, nullptr, nullptr, &serverConfigs)) {
            for (const auto& entry : serverConfigs) {
                ConfigInfo info;

                auto copyStringField = [](const String& src, char* buf, size_t bufSize) {
                    size_t len = (src.length < bufSize - 1) ? src.length : bufSize - 1;
                    if (src.data && len > 0) memcpy(buf, src.data, len);
                    buf[len] = '\0';
                };

                char idBuf[64], nameBuf[256], descBuf[512], authorBuf[128], dateBuf[64];

                copyStringField(entry.id, idBuf, sizeof(idBuf));
                copyStringField(entry.name, nameBuf, sizeof(nameBuf));
                copyStringField(entry.description, descBuf, sizeof(descBuf));

                info.id = std::string(idBuf);
                secureStrSet(info.name, nameBuf);
                secureStrSet(info.description, descBuf);

                copyStringField(entry.author, authorBuf, sizeof(authorBuf));
                info.author = std::string(authorBuf);

                copyStringField(entry.createdDate, dateBuf, sizeof(dateBuf));
                info.createdDate = std::string(dateBuf);

                info.isLoaded = (m_currentConfigId == info.id && !m_currentConfigId.empty());

                SecureZeroMemory(idBuf, sizeof(idBuf));
                SecureZeroMemory(nameBuf, sizeof(nameBuf));
                SecureZeroMemory(descBuf, sizeof(descBuf));
                SecureZeroMemory(authorBuf, sizeof(authorBuf));
                SecureZeroMemory(dateBuf, sizeof(dateBuf));

                configs.push_back(std::move(info));
            }
            return configs;
        }
    }

    return configs;
}

ConfigInfo* ConfigManager::getCurrentConfig() {

    return nullptr;
}

bool ConfigManager::isConfigLoaded(const std::string& configId) const {
    return m_currentConfigId == configId;
}

void ConfigManager::clearCache() {

}

void ConfigManager::secureCleanup() {

    secureErase(m_currentConfigId);
}

void ConfigManager::unloadCurrentConfig() {
    secureErase(m_currentConfigId);
}

bool ConfigManager::isConfigCached(const std::string& configId) const {

    return false;
}

whip::WhipJsonValue ConfigManager::serializeModuleSettings(IModule* module) {
    whip::WhipJsonValue moduleJson;

    if (module->getBindType() != BindType::HOLD) {
        moduleJson["enabled"] = module->isEnabled();
    }

    auto& settingsHandler = SettingsHandler::getInstance();
    if (!settingsHandler.hasSettings(module)) {
        return moduleJson;
    }

    const auto& settings = settingsHandler.getModuleSettings(module);
    auto& codecRegistry = SettingCodecRegistry::getInstance();

    for (const auto& setting : settings) {
        if (!setting) continue;

        SettingType type = setting->getType();

        if (type == SettingType::TEXT) {
            continue;
        }

        ISettingCodec* codec = codecRegistry.getCodec(type);
        if (!codec) {

            continue;
        }

        whip::WhipJsonValue settingJson = codec->encode(setting.get());
        moduleJson["settings"][setting->getName()] = std::move(settingJson);
    }

    return moduleJson;
}

void ConfigManager::deserializeModuleSettings(IModule* module, const whip::WhipJsonValue& moduleJson) {
    bool moduleEnabled = false;

    if (module->getBindType() != BindType::HOLD) {
        if (moduleJson.contains("enabled") && moduleJson["enabled"].is_boolean()) {
            moduleEnabled = moduleJson["enabled"];
            module->setEnabled(moduleEnabled);
        }
    }

    if (!moduleJson.contains("settings")) {
        return;
    }

    auto& settingsHandler = SettingsHandler::getInstance();
    if (!settingsHandler.hasSettings(module)) {
        return;
    }

    const auto& settings = settingsHandler.getModuleSettings(module);
    auto& codecRegistry = SettingCodecRegistry::getInstance();

    for (const auto& setting : settings) {
        if (!setting) continue;

        const char* settingName = setting->getName();

        if (!moduleJson["settings"].contains(settingName)) {
            continue;
        }

        const auto& settingJson = moduleJson["settings"][settingName];

        SettingType type = setting->getType();
        ISettingCodec* codec = codecRegistry.getCodec(type);
        if (!codec) {
            continue;
        }

        CodecResult validationResult = codec->validate(settingJson);
        if (!validationResult.success) {
            continue;
        }

        codec->decode(setting.get(), settingJson);
    }

    if (module->getBindType() != BindType::HOLD && module->hasKeybind()) {
        BindManager::getInstance().syncBindStateForModule(module, moduleEnabled);
    }
}

DynamicTrackedString ConfigManager::getCurrentTimeString() const {
    char buffer[64];
    auto now = std::time(nullptr);
    auto* timeinfo = std::localtime(&now);
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    DynamicTrackedString result(buffer);
    SecureZeroMemory(buffer, sizeof(buffer));
    return result;
}

whip::WhipJsonValue ConfigManager::createConfigJson(const ConfigMetadata& metadata) {
    whip::WhipJsonValue configJson;

    configJson["id"] = metadata.id;
    configJson["name"] = metadata.name ? metadata.name : "";
    configJson["metadata"]["version"] = metadata.version;
    configJson["metadata"]["description"] = metadata.description ? metadata.description : "";
    configJson["metadata"]["author"] = metadata.author;
    configJson["metadata"]["created"] = metadata.created;
    configJson["metadata"]["modified"] = metadata.modified;
    configJson["modules"] = whip::WhipJsonValue::object();

    return configJson;
}

bool ConfigManager::validateConfigJson(const whip::WhipJsonValue& configJson) const {

    return configJson.contains("id") &&
           configJson.contains("metadata") &&
           configJson.contains("modules") &&
           configJson["metadata"].contains("version");
}

ConfigManager& ConfigManager::getInstance() {
    static ConfigManager instance;
    return instance;
}
