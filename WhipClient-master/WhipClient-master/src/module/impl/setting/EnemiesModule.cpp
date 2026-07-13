#include "../../../../includes/module/impl/setting/EnemiesModule.h"
#include <widgets.h>
#include "../../../../includes/module/impl/visual/NotificationModule.h"
#include "../../../../includes/wrapper/java/util/UUID.h"
#include "../../../../includes/handler/ModuleHandler.h"
#include "util/ClientStrings.h"
#include "wrapper/minecraft/client/minecraft.h"

#include <chrono>
#include <algorithm>
#include <mutex>
#include "../../../../includes/util/MojangAPIUtils.h"
#include "../../../../includes/manager/ConfigManager.h"

bool EnemiesModule::isEnemy(Entity& entity) {
    const JavaUUID entityUUID = entity.getEntityUniqueID();
    if (entityUUID.isNull()) {
        return false;
    }

    UUIDData entityUUIDData = entityUUID.toUUIDData();

    for (auto enemyUUIDData : enemyUUIDEntities) {
        if (entityUUIDData.equals(enemyUUIDData)) {
            return true;
        }
    }
    return false;
}

bool EnemiesModule::isEnemyByName(const std::string& name) {
    for (const auto& enemyName : enemyNames) {
        if (enemyName == name) {
            return true;
        }
    }
    return false;
}

void EnemiesModule::addEnemy(Entity entity) {

    if (isEnemy(entity)) {
        return;
    }

    enemyEntities.push_back(entity.entityId());

    auto entityUUID = entity.getEntityUniqueID();
    if (entityUUID.isNull()) {
        return;
    }

    UUIDData entityUUIDData = entityUUID.toUUIDData();
    enemyUUIDEntities.push_back(entityUUIDData);

    JniScope scope;
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
        jstring entityName = entity.getName();
        std::string name = JavaString::jstringToString(scope.getEnv(), entityName);
        enemyNames.push_back(name);
    } else {
        enemyNames.push_back(Strings::lblUnknown());
    }
}

UUIDData EnemiesModule::getUUIDFromName(const std::string& name, JniScope& scope) {

    Minecraft theMc = Minecraft::getMinecraft(scope.getEnv());
    if (!theMc.isNull()) {
        WorldClient theWorld = theMc.theWorld();
        if (!theWorld.isNull()) {
            ArrayList playerEntities = theWorld.playerEntities();
            if (!playerEntities.isNull()) {
                JNIEnv* _env = scope.getEnv();
                int playerEntitiesSize = playerEntities.size();
                if (_env->ExceptionCheck()) { _env->ExceptionClear(); return {}; }

                for (int i = 0; i < playerEntitiesSize; i++) {
                    JavaObject playerObj = playerEntities.get(i);
                    if (_env->ExceptionCheck()) { _env->ExceptionClear(); break; }
                    EntityPlayer player = playerObj.convertTo<EntityPlayer>();

                    std::string playerName;
                    if (!player.isNull()) {
                        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
                            jstring jPlayerName = player.getName();
                            playerName = JavaString::jstringToString(scope.getEnv(), jPlayerName);
                        }
                        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
                            jstring jPlayerName = player.getCommandSenderName();
                            playerName = JavaString::jstringToString(scope.getEnv(), jPlayerName);
                        }

                        if (playerName == name) {
                            secureErase(playerName);
                            JavaUUID uuid = player.getEntityUniqueID();
                            if (!uuid.isNull()) {
                                UUIDData uuidData = uuid.toUUIDData();
                                return uuidData;
                            }
                        }
                        secureErase(playerName);
                    }
                }
            }
        }
    }

    return UUIDData();
}

void EnemiesModule::addEnemyByName(const std::string& name) {
    if (name.empty() || isEnemyByName(name)) {
        return;
    }

    JniScope scope;
    UUIDData enemyUUID = getUUIDFromName(name, scope);

    if (enemyUUID.hashCode == 0) {
        enemyNames.push_back(name);
        enemyUUIDEntities.push_back(UUIDData());
        std::string message = name + Strings::msgAddedOffline();
        NotificationModule::addCustomNotification(message, ADDED_COLOR);
        secureErase(message);
    } else {
        enemyNames.push_back(name);
        enemyUUIDEntities.push_back(enemyUUID);
        std::string message = name + Strings::msgEnemyAdded();
        NotificationModule::addCustomNotification(message, ADDED_COLOR);
        secureErase(message);
    }

}

void EnemiesModule::addEnemyByNameAsync(const std::string& name) {
    if (name.empty() || isEnemyByName(name)) {
        return;
    }

    JniScope scope;
    UUIDData enemyUUID = getUUIDFromName(name, scope);

    if (enemyUUID.hashCode != 0) {
        enemyNames.push_back(name);
        enemyUUIDEntities.push_back(enemyUUID);
        std::string message = name + Strings::msgEnemyAdded();
        NotificationModule::addCustomNotification(message, ADDED_COLOR);
        secureErase(message);
        return;
    }

    {
        std::lock_guard lock(pendingMutex);
        for (const auto& [username, startTime] : pendingRequests) {
            if (username == name) {
                return;
            }
        }

        pendingRequests.push_back({name, std::chrono::steady_clock::now()});
    }

    MojangAPIThreadContext* context = new MojangAPIThreadContext{name, this};

    HANDLE threadHandle = CreateThread(
        nullptr,
        0,
        mojangAPIThreadProc,
        context,
        0,
        nullptr
    );

    if (threadHandle != nullptr) {
        std::lock_guard lock(threadHandlesMutex);
        activeThreadHandles.push_back(threadHandle);
    } else {
        secureErase(context->username);
        delete context;
        {
            std::lock_guard lock(pendingMutex);
            auto toRemove = std::remove_if(pendingRequests.begin(), pendingRequests.end(),
                [&name](PendingRequest& req) {
                    if (req.username == name) {
                        secureErase(req.username);
                        return true;
                    }
                    return false;
                });
            pendingRequests.erase(toRemove, pendingRequests.end());
        }

        enemyNames.push_back(name);
        enemyUUIDEntities.push_back(UUIDData());
        std::string message = name + Strings::msgAddedOffline();
        NotificationModule::addCustomNotification(message, ADDED_COLOR);
        secureErase(message);
    }
}

void EnemiesModule::removeEnemy(Entity entity) {

    auto position = find(enemyEntities.begin(), enemyEntities.end(), entity.entityId());
    if (position != enemyEntities.end()) {
        size_t index = std::distance(enemyEntities.begin(), position);
        enemyEntities.erase(position);

        if (index < enemyNames.size()) {
            enemyNames.erase(enemyNames.begin() + index);
        }
    }

    auto entityUUID = entity.getEntityUniqueID();
    if (entityUUID.isNull()) {
        return;
    }

    UUIDData entityUUIDData = entityUUID.toUUIDData();
    auto uuidPosition = std::find_if(enemyUUIDEntities.begin(), enemyUUIDEntities.end(),
        [&entityUUIDData](const UUIDData& enemyUUIDData) {
            return entityUUIDData.equals(enemyUUIDData);
        });

    if (uuidPosition != enemyUUIDEntities.end()) {
        enemyUUIDEntities.erase(uuidPosition);
    }

}

void EnemiesModule::removeEnemyByIndex(size_t index) {

    if (index < enemyUUIDEntities.size()) {
        enemyUUIDEntities.erase(enemyUUIDEntities.begin() + index);
    }
    if (index < enemyNames.size()) {
        enemyNames.erase(enemyNames.begin() + index);
    }
    if (index < enemyEntities.size()) {
        enemyEntities.erase(enemyEntities.begin() + index);
    }
}

void EnemiesModule::clearEnemies() {
    enemyEntities.clear();
    enemyUUIDEntities.clear();

    for (auto& name : enemyNames) {
        SecureZeroMemory(name.data(), name.capacity());
    }
    enemyNames.clear();
}

EnemiesModule::~EnemiesModule() {
    std::lock_guard lock(threadHandlesMutex);

    for (HANDLE handle : activeThreadHandles) {
        if (handle != nullptr) {
            DWORD result = WaitForSingleObject(handle, 5000);

            if (result == WAIT_TIMEOUT) {
                TerminateThread(handle, 1);
            }

            CloseHandle(handle);
        }
    }

    activeThreadHandles.clear();
    clearInstanceBuffer();
}

int EnemiesModule::getEnemyCount() const {
    return enemyUUIDEntities.size();
}

double EnemiesModule::getDistance(EntityClientPlayerMP& thePlayer, EntityPlayer& player) {
    return sqrt(pow(thePlayer.posX() - player.posX(), 2)
        + pow(thePlayer.posY() - player.posY(), 2)
        + pow(thePlayer.posZ() - player.posZ(), 2));
}

void EnemiesModule::onRender(const std::unique_ptr<c_widgets> &widgets) {
    bool shouldClear = false;

    if (widgets->button2(Strings::btnAddEnemy())) {
        std::string enemyName(inputBuffer);

        if (!enemyName.empty()) {
            addEnemyByNameAsync(enemyName);
            shouldClear = true;
        }
        secureErase(enemyName);
    }

    if (widgets->config_text_field(Strings::lblEnemiesInput(), inputBuffer, sizeof(inputBuffer))) {
        if (ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter)) {
            std::string enemyName(inputBuffer);
            if (!enemyName.empty()) {
                addEnemyByNameAsync(enemyName);
                shouldClear = true;
            }
            secureErase(enemyName);
        }
    }

    if (shouldClear) {
        memset(inputBuffer, 0, sizeof(inputBuffer));
        ImGui::ClearActiveID();
    }
}

void EnemiesModule::onRenderConditional(const std::unique_ptr<c_widgets> &widgets) {
    if (widgets->button2(Strings::btnClearAllEnemies())) {

        if (getEnemyCount() > 0) {
            std::string message = std::to_string(getEnemyCount()) + Strings::msgEnemiesRemoved();
            clearEnemies();
            NotificationModule::addCustomNotification(message, REMOVED_COLOR);
            secureErase(message);
        } else {
            NotificationModule::addCustomNotification(Strings::msgNoEnemiesToRemove(), REMOVED_COLOR);
        }
    }

    widgets->child2(Strings::lblEnemiesList());
    {
        for (size_t i = 0; i < enemyNames.size(); i++) {
            PushID(static_cast<int>(i));
            if (widgets->button3(Strings::btnRemove(), enemyNames[i].c_str())) {
                std::string message = enemyNames[i] + Strings::msgEnemyRemoved();
                removeEnemyByIndex(i);
                NotificationModule::addCustomNotification(message, REMOVED_COLOR);
                SecureZeroMemory(message.data(), message.capacity());
                message.clear();
                PopID();
                break;
            }
            PopID();
        }
    }
    widgets->end_child();
}

void EnemiesModule::onUpdate(JniScope& scope) {
    if (this->clearEnemiesKey != 0) {
        if (GetAsyncKeyState(this->clearEnemiesKey) & 0x8000) {
            if (!this->clearKeyWasPressed) {
                std::string message = std::to_string(getEnemyCount()) + Strings::msgEnemiesRemoved();
                this->clearEnemies();
                NotificationModule::addCustomNotification(message, this->REMOVED_COLOR);
                SecureZeroMemory(message.data(), message.capacity());
                message.clear();
                this->clearKeyWasPressed = true;
            }
        }
        else {
            this->clearKeyWasPressed = false;
        }
    }

    Minecraft theMc = Minecraft::getMinecraft(scope.getEnv());
    if (theMc.isNull()) return;

    if (this->addNearbyEnemiesKey != 0) {
        if (GetAsyncKeyState(this->addNearbyEnemiesKey) & 0x8000) {
            if (!this->addNearbyKeyWasPressed) {
                this->addNearbyKeyWasPressed = true;

                WorldClient theWorld = theMc.theWorld();
                if (theWorld.isNull()) {
                    return;
                }

                EntityClientPlayerMP thePlayer = theMc.thePlayer();
                if (thePlayer.isNull()) {
                    return;
                }

                ArrayList playerEntities = theWorld.playerEntities();
                if (playerEntities.isNull()) {
                    return;
                }

                int oldSize = getEnemyCount();
                int playerEntitiesSize = playerEntities.size();

                for (int i = 0; i < playerEntitiesSize; i++) {
                    JavaObject playerObj = playerEntities.get(i);
                    EntityPlayer player = playerObj.convertTo<EntityPlayer>();

                    if (player.isNull() || thePlayer.entityId() == player.entityId()) {
                        continue;
                    }

                    double distance = getDistance(thePlayer, player);

                    if (distance > 15) {
                        continue;
                    }

                    addEnemy(player);
                }

                int addedCount = getEnemyCount() - oldSize;
                std::string message = std::to_string(addedCount) + Strings::msgEnemiesAdded();
                NotificationModule::addCustomNotification(message, this->ADDED_COLOR);
                SecureZeroMemory(message.data(), message.capacity());
                message.clear();
            }
        }
        else {
            addNearbyKeyWasPressed = false;
        }
    }

    cleanupCompletedThreads();
}

void EnemiesModule::onUUIDResolved(const std::string& username, const UUIDData& uuid) {
    enemyNames.push_back(username);
    enemyUUIDEntities.push_back(uuid);

    std::string message = username + " " + Strings::msgEnemyAdded() + " (bypass method)";
    NotificationModule::addCustomNotification(message, ADDED_COLOR);
    secureErase(message);
}

void EnemiesModule::onUUIDLookupFailed(const std::string& username) {
    enemyNames.push_back(username);
    enemyUUIDEntities.push_back(UUIDData());

    std::string message = username + " " + Strings::msgAddedOffline();
    NotificationModule::addCustomNotification(message, ADDED_COLOR);
    secureErase(message);
}

void EnemiesModule::cleanupCompletedThreads() {
    {
        std::lock_guard lock(threadHandlesMutex);

        auto it = activeThreadHandles.begin();
        while (it != activeThreadHandles.end()) {
            DWORD result = WaitForSingleObject(*it, 0);

            if (result == WAIT_OBJECT_0) {
                CloseHandle(*it);
                it = activeThreadHandles.erase(it);
            } else {
                ++it;
            }
        }
    }

    {
        std::lock_guard lock(pendingMutex);
        auto now = std::chrono::steady_clock::now();

        auto toRemove = std::remove_if(pendingRequests.begin(), pendingRequests.end(),
            [&now](PendingRequest& req) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - req.startTime
                ).count();
                if (elapsed > 10) {
                    secureErase(req.username);
                    return true;
                }
                return false;
            });
        pendingRequests.erase(toRemove, pendingRequests.end());
    }
}

DWORD WINAPI EnemiesModule::mojangAPIThreadProc(LPVOID param) {
    MojangAPIThreadContext* context = static_cast<MojangAPIThreadContext*>(param);
    if (!context) return 1;

    std::string username = context->username;
    EnemiesModule* module = context->moduleInstance;
    secureErase(context->username);
    delete context;

    UUIDData uuidData = MojangAPIUtils::fetchUUIDFromUsername(username);
    {
        std::lock_guard lock(module->pendingMutex);
        module->pendingRequests.erase(
            std::remove_if(module->pendingRequests.begin(), module->pendingRequests.end(),
                [&username](const PendingRequest& req) { return req.username == username; }),
            module->pendingRequests.end()
        );
    }

    if (uuidData.hashCode != 0) {
        module->onUUIDResolved(username, uuidData);
    } else {
        module->onUUIDLookupFailed(username);
    }

    secureErase(username);
    return 0;
}

REGISTER_MODULE(EnemiesModule, ModuleType::ENEMY)
