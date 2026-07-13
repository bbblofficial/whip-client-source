#pragma once

#include "../../base/ListenedBaseModule.h"
#include "event/sub/Render2dEvent.h"
#include "event/sub/DispatchKeypressesEvent.h"
#include "event/sub/ChannelReadEvent.h"
#include "event/sub/AddSendQueueEvent.h"
#include "util/ClientStrings.h"

#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <mutex>
#include <string>
#include <chrono>
#include <imgui.h>

class HitHealCounterModule final : public ListenedBaseModule<HitHealCounterModule, ModuleType::HIT_HEAL_COUNTER, CategoryType::VISUAL> {
    friend class BaseModule;

    int mode = 0;
    static constexpr float radius = 256.0f;
    float scale = 1.8f;
    float posNX = 0.02f;
    float posNY = 0.35f;
    static constexpr bool blurEnabled = true;
    float blurOpacity = 0.9f;

    float currentScale_ = -1.0f;
    bool dragging_ = false;
    ImVec2 dragOffset_{ 0.0f, 0.0f };
    bool resizing_ = false;
    float resizeBaseScale_ = 0.0f;
    float resizeBaseMouseX_ = 0.0f;

    struct PendingAttack {
        int targetId;
        long long timestamp;
    };
    std::deque<PendingAttack> pendingAttacks_;
    mutable std::mutex pendingMutex_;
    static constexpr long long ATTACK_CONFIRM_WINDOW_MS = 500;

    long long targetOutOfRangeSince_ = 0;
    long long noEnemiesInRangeSince_ = 0;
    static constexpr long long OUT_OF_RANGE_RESET_MS = 3000;

    jclass s0eClass_ = nullptr;

    jfieldID s0e_typeField_ = nullptr;
    jfieldID s0e_xField_ = nullptr;
    jfieldID s0e_yField_ = nullptr;
    jfieldID s0e_zField_ = nullptr;
    jfieldID s0e_dataField_ = nullptr;
    jfieldID s0e_entityIdField_ = nullptr;
    bool s0eInitialized_ = false;
    void initS0EFields(JNIEnv* env);
    void handleSpawnObject(JNIEnv* env, jobject packet);

    struct RecentSplash {
        int packX;
        int packY;
        int packZ;
        long long timestamp;
    };
    std::deque<RecentSplash> recentSpawnIds_;
    static constexpr long long SPAWN_DEDUP_WINDOW_MS = 250;

    static constexpr int SPAWN_POS_TOLERANCE = 16;

    bool pearlInFlight_ = false;

    int myHits_ = 0;
    int myPots_ = 0;
    int enemyHits_ = 0;
    int enemyPots_ = 0;
    int targetEntityId_ = -1;
    std::string targetName_;

    int teamHits_ = 0;
    int teamPots_ = 0;
    int enemyTeamHits_ = 0;
    int enemyTeamPots_ = 0;

    struct RenderSnapshot {
        int mode = 0;
        int myHits = 0, myPots = 0;
        int enemyHits = 0, enemyPots = 0;
        int teamHits = 0, teamPots = 0;
        int enemyTeamHits = 0, enemyTeamPots = 0;
        bool hasTarget = false;
        char targetName[64] = {};
    };
    mutable std::mutex snapMutex_;
    RenderSnapshot snap_{};

    int myEntityId_ = -1;

    [[nodiscard]] long long nowMs() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

public:
    HitHealCounterModule() : ListenedBaseModule(BindType::TOGGLE, 0) {}

    void onLoad() override;
    void onDisable() override;
    [[nodiscard]] bool shouldShowInArraylist() const override { return false; }

protected:
    void registerEvents() override;

private:
    void onChannelRead(const ChannelReadEvent& event);
    void onPacketSend(const AddSendQueueEvent& event);
    void onTick(const OnRunTickEvent& event);
    void onRender2d(const Render2dEvent& event);

    bool wasMyAttack(int entityId);
    void resetCounters();
    void pushSnapshot();

    bool isFriendOrMe(JNIEnv* env, int entityId);
    std::string getPlayerName(JNIEnv* env, int entityId);
};
