#pragma once
#include "../../../hud/renderer/IArraylistRenderer.h"
#include "../../base/SharedThreadBaseModule.h"
#include "../../ModuleType.h"
#include "../../CategoryType.h"
#include "../../../util/JniScope.h"
#include "../../../setting/SettingMacros.h"
#include <vector>
#include <string>
#include <mutex>
#include <chrono>
#include <windows.h>
#include <imgui.h>
#include "../../../wrapper/java/util/UUID.h"
#include "util/ClientStrings.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"

class EnemiesModule;

struct MojangAPIThreadContext {
    std::string username;
    EnemiesModule* moduleInstance;
};

class EnemiesModule final : public SharedThreadBaseModule<EnemiesModule, ModuleType::ENEMY, CategoryType::SETTING> {
    std::vector<int> enemyEntities;
    std::vector<UUIDData> enemyUUIDEntities;
    std::vector<std::string> enemyNames;
    bool pickBlockPressed = false;
    int clearEnemiesKey = 0;
    int addEnemiesKey = 5;
    bool clearKeyWasPressed = false;
    int addNearbyEnemiesKey = 0;
    bool addNearbyKeyWasPressed = false;

    char inputBuffer[64] = "";

    static constexpr ImColor ADDED_COLOR = ImColor(255, 87, 87, 255);
    static constexpr ImColor REMOVED_COLOR = ImColor(135, 206, 235, 255);

    std::vector<HANDLE> activeThreadHandles;
    mutable std::mutex threadHandlesMutex;

    struct PendingRequest {
        std::string username;
        std::chrono::steady_clock::time_point startTime;
    };
    std::vector<PendingRequest> pendingRequests;
    mutable std::mutex pendingMutex;

protected:
    void onUpdate(JniScope& scope) override;
    void onRender(const std::unique_ptr<c_widgets> &widgets) override;
    void onRenderConditional(const std::unique_ptr<c_widgets> &widgets) override;

public:
    EnemiesModule() = default;
    ~EnemiesModule() override;

    void onLoad() override {
        SharedThreadBaseModule::onLoad();

        KEYBIND_SETTING_CONDITIONAL(addEnemiesKey, 5);
        KEYBIND_SETTING_CONDITIONAL(addNearbyEnemiesKey, 0);
        KEYBIND_SETTING_CONDITIONAL(clearEnemiesKey, 0);
    }

    bool isEnemy(Entity& entity);
    bool isEnemyByName(const std::string& name);
    void addEnemy(Entity entity);
    void addEnemyByName(const std::string& name);
    void addEnemyByNameAsync(const std::string& name);
    void removeEnemy(Entity entity);
    void removeEnemyByIndex(size_t index);
    void clearEnemies();
    int getEnemyCount() const;

    void addEnemyById(int id) { enemyEntities.push_back(id); }

    const std::vector<int>& getEnemyEntities() const { return enemyEntities; }
    const std::vector<UUIDData>& getEnemyUUIDEntities() const { return enemyUUIDEntities; }
    const std::vector<std::string>& getEnemyNames() const { return enemyNames; }

private:
	mutable char instanceBuffer[64] = {0};

public:

    FORMAT_FLAGS("%d", getEnemyCount())

private:
    double getDistance(EntityClientPlayerMP& thePlayer, EntityPlayer& player);

    UUIDData getUUIDFromName(const std::string& name, JniScope& scope);

    static DWORD WINAPI mojangAPIThreadProc(LPVOID param);

    void onUUIDResolved(const std::string& username, const UUIDData& uuid);

    void onUUIDLookupFailed(const std::string& username);

    void cleanupCompletedThreads();
};
