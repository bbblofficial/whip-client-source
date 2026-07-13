#include "../../../../includes/module/impl/visual/HitHealCounterModule.h"
#include "../../../../includes/wrapper/minecraft/client/Minecraft.h"
#include "../../../../includes/wrapper/minecraft/world/World.h"
#include "../../../../includes/wrapper/java/util/ArrayList.h"
#include "../../../../includes/module/impl/setting/FriendsModule.h"
#include "../../../../includes/handler/ModuleHandler.h"
#include "../../../../includes/handler/MappingHandler.h"
#include "../../../../includes/wrapper/minecraft/network/play/server/S19PacketEntityStatus.h"
#include "../../../../includes/wrapper/minecraft/network/play/client/C02PacketUseEntity.h"

#include "setting/SettingMacros.h"
#include "gui/Gui.h"
#include "includes.h"
#include "util/KawaseBlur.h"

#include <cmath>
#include <algorithm>
#include <cstring>

void HitHealCounterModule::onLoad() {
    ListenedBaseModule::onLoad();

    REGISTER_FLOAT(posNX, 0.02f);
    REGISTER_FLOAT(posNY, 0.35f);

    COMBO_SETTING(mode, Strings::modeSolo(), Strings::modeTeam());
    FLOAT_SLIDER(scale, 1.8f, 0.5f, 3.0f);
    FLOAT_SLIDER(blurOpacity, 0.9f, 0.0f, 1.0f);

    BUTTON_SETTING_CONDITIONAL(Strings::btnClear(), [this]() {
        resetCounters();
        pushSnapshot();
    });
}

void HitHealCounterModule::onDisable() {
    ListenedBaseModule::onDisable();
    resetCounters();
    pushSnapshot();
}

void HitHealCounterModule::registerEvents() {
    subscribe<ChannelReadEvent>([this](const ChannelReadEvent& event) {
        onChannelRead(event);
    }, EventPriority::DEFAULT, true);

    subscribe<AddSendQueueEvent>([this](const AddSendQueueEvent& event) {
        onPacketSend(event);
    }, EventPriority::DEFAULT, true);

    subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
        onTick(event);
    });

    subscribe<Render2dEvent>([this](const Render2dEvent& event) {
        onRender2d(event);
    });
}

void HitHealCounterModule::initS0EFields(JNIEnv* env) {
    if (s0eInitialized_) return;
    s0eInitialized_ = true;

    s0eClass_ = Mappings::getInstance().getClass("S0EPacketSpawnObject");
    if (!s0eClass_) return;

    s0e_xField_        = Mappings::getInstance().getField("S0EPacketSpawnObject#x");
    s0e_yField_        = Mappings::getInstance().getField("S0EPacketSpawnObject#y");
    s0e_zField_        = Mappings::getInstance().getField("S0EPacketSpawnObject#z");
    s0e_typeField_     = Mappings::getInstance().getField("S0EPacketSpawnObject#type");
    s0e_dataField_     = Mappings::getInstance().getField("S0EPacketSpawnObject#field_149020_k");
    s0e_entityIdField_ = Mappings::getInstance().getField("S0EPacketSpawnObject#entityId");

    if (env->ExceptionCheck()) env->ExceptionClear();
}

void HitHealCounterModule::handleSpawnObject(JNIEnv* env, jobject packet) {
    if (!s0e_typeField_ || !s0e_xField_ || !s0e_yField_ || !s0e_zField_) return;

    int type = env->GetIntField(packet, s0e_typeField_);

    if (type == 65) {

        Minecraft mc = Minecraft::getMinecraft(env);
        if (!mc.isNull()) {
            EntityClientPlayerMP thePlayer = mc.thePlayer();
            if (!thePlayer.isNull() && s0e_xField_ && s0e_yField_ && s0e_zField_) {
                double px = env->GetIntField(packet, s0e_xField_) / 32.0;
                double py = env->GetIntField(packet, s0e_yField_) / 32.0;
                double pz = env->GetIntField(packet, s0e_zField_) / 32.0;
                double dx = thePlayer.posX() - px;
                double dy = thePlayer.posY() - py;
                double dz = thePlayer.posZ() - pz;
                if (dx*dx + dy*dy + dz*dz <= 4.0 * 4.0) {
                    pearlInFlight_ = true;
                }
            }
        }
        return;
    }

    if (type != 73) return;

    if (s0e_dataField_) {
        int data = env->GetIntField(packet, s0e_dataField_);

        if (data != 16421 && data != 16453) return;
    }

    const int packX = env->GetIntField(packet, s0e_xField_);
    const int packY = env->GetIntField(packet, s0e_yField_);
    const int packZ = env->GetIntField(packet, s0e_zField_);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }

    {
        const long long now = nowMs();
        while (!recentSpawnIds_.empty() &&
               now - recentSpawnIds_.front().timestamp > SPAWN_DEDUP_WINDOW_MS) {
            recentSpawnIds_.pop_front();
        }
        for (const auto& e : recentSpawnIds_) {
            if (std::abs(e.packX - packX) <= SPAWN_POS_TOLERANCE &&
                std::abs(e.packY - packY) <= SPAWN_POS_TOLERANCE &&
                std::abs(e.packZ - packZ) <= SPAWN_POS_TOLERANCE) {
                return;
            }
        }
        recentSpawnIds_.push_back({packX, packY, packZ, now});
        if (recentSpawnIds_.size() > 32) recentSpawnIds_.pop_front();
    }

    double posX = packX / 32.0;
    double posY = packY / 32.0;
    double posZ = packZ / 32.0;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    WorldClient world = mc.theWorld();
    if (world.isNull()) return;
    EntityClientPlayerMP thePlayer = mc.thePlayer();
    if (thePlayer.isNull()) return;

    ArrayList playerList = world.playerEntities();
    if (playerList.isNull()) return;

    int count = playerList.size();
    int nearestId = -1;
    double nearestDist = 10.0 * 10.0;

    for (int i = 0; i < count; i++) {
        JavaObject obj = playerList.get(i);
        if (obj.isNull()) continue;
        Entity entity(env, obj.getObj());
        entity.setDeleteRef(false);
        if (entity.isNull()) continue;

        double dx = entity.posX() - posX;
        double dy = entity.posY() - posY;
        double dz = entity.posZ() - posZ;
        double distSq = dx * dx + dy * dy + dz * dz;

        if (distSq < nearestDist) {
            nearestDist = distSq;
            nearestId = entity.entityId();
        }
    }

    if (nearestId == -1) return;
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }

    {
        double dx = thePlayer.posX() - posX;
        double dy = thePlayer.posY() - posY;
        double dz = thePlayer.posZ() - posZ;
        if (dx * dx + dy * dy + dz * dz > (double)radius * radius) return;
    }

    bool throwerIsFriendOrMe = isFriendOrMe(env, nearestId);

    if (mode == 0) {
        if (nearestId == myEntityId_) {
            myPots_++;
        } else if (nearestId == targetEntityId_ || (targetEntityId_ == -1 && !throwerIsFriendOrMe)) {
            enemyPots_++;
        }
    } else {
        if (throwerIsFriendOrMe) {
            teamPots_++;
        } else {
            enemyTeamPots_++;
        }
    }

    if (env->ExceptionCheck()) env->ExceptionClear();
}

bool HitHealCounterModule::wasMyAttack(int entityId) {
    long long now = nowMs();
    std::lock_guard<std::mutex> lock(pendingMutex_);
    for (auto it = pendingAttacks_.begin(); it != pendingAttacks_.end(); ++it) {
        if (it->targetId == entityId && (now - it->timestamp) < ATTACK_CONFIRM_WINDOW_MS) {
            pendingAttacks_.erase(it);
            return true;
        }
    }
    return false;
}

bool HitHealCounterModule::isFriendOrMe(JNIEnv* env, int entityId) {
    if (entityId == myEntityId_) return true;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return false;
    WorldClient world = mc.theWorld();
    if (world.isNull()) return false;

    ArrayList playerList = world.playerEntities();
    if (playerList.isNull()) return false;

    int count = playerList.size();
    for (int i = 0; i < count; i++) {
        JavaObject obj = playerList.get(i);
        if (obj.isNull()) continue;
        Entity entity(env, obj.getObj());
        entity.setDeleteRef(false);
        if (entity.isNull()) continue;
        if (entity.entityId() == entityId) {
            return FriendsModule::getInstance().isFriend(entity);
        }
    }
    return false;
}

std::string HitHealCounterModule::getPlayerName(JNIEnv* env, int entityId) {
    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return "";
    WorldClient world = mc.theWorld();
    if (world.isNull()) return "";

    ArrayList playerList = world.playerEntities();
    if (playerList.isNull()) return "";

    int count = playerList.size();
    for (int i = 0; i < count; i++) {
        JavaObject obj = playerList.get(i);
        if (obj.isNull()) continue;
        Entity entity(env, obj.getObj());
        entity.setDeleteRef(false);
        if (entity.isNull()) continue;
        if (entity.entityId() == entityId) {
            jstring name = entity.getName();
            if (!name) return "";
            std::string result = JavaString::jstringToString(env, name);
            env->DeleteLocalRef(name);
            return result;
        }
    }
    return "";
}

void HitHealCounterModule::onPacketSend(const AddSendQueueEvent& event) {
    if (!this->enable) return;

    JNIEnv* env = event.getEnv();
    if (!env) return;

    jclass c02Class = Mappings::getInstance().getClass("C02PacketUseEntity");
    if (!c02Class) { return; }
    if (!env->IsInstanceOf(event.getPacketObject(), c02Class)) return;

    C02PacketUseEntity packet(env, event.getPacketObject());
    packet.setDeleteRef(false);
    if (packet.isNull()) { return; }
    if (!packet.isAttack()) { return; }

    int targetId = packet.entityId();
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }

    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingAttacks_.push_back(PendingAttack{ targetId, nowMs() });

        long long now = nowMs();
        while (!pendingAttacks_.empty() && (now - pendingAttacks_.front().timestamp) > ATTACK_CONFIRM_WINDOW_MS) {
            pendingAttacks_.pop_front();
        }
    }

    if (mode == 0 && targetEntityId_ == -1) {
        targetEntityId_ = targetId;
        targetName_ = getPlayerName(env, targetId);
    }
}

void HitHealCounterModule::onChannelRead(const ChannelReadEvent& event) {
    if (!this->enable) return;

    JNIEnv* env = event.getEnv();
    if (!env) return;

    jobject packet = event.getPacketObject();
    if (!packet) return;

    initS0EFields(env);
    if (s0eClass_ && env->IsInstanceOf(packet, s0eClass_)) {
        handleSpawnObject(env, packet);
        if (env->ExceptionCheck()) env->ExceptionClear();
        return;
    }

    jclass s19Class = Mappings::getInstance().getClass("S19PacketEntityStatus");
    if (!s19Class) { return; }
    if (!env->IsInstanceOf(packet, s19Class)) return;

    S19PacketEntityStatus s19Packet(env, event.getPacketObject());
    s19Packet.setDeleteRef(false);
    if (s19Packet.isNull()) { return; }

    jbyte opcode = s19Packet.getLogicOpcode();

    if (s19Packet.isDeath()) {
        int deadId = s19Packet.entityId();
        if (env->ExceptionCheck()) { env->ExceptionClear(); return; }

        if (mode == 0) {

            if (deadId == myEntityId_ || deadId == targetEntityId_) {
                resetCounters();
                pushSnapshot();
                return;
            }
        } else {

            if (deadId == myEntityId_) {
                resetCounters();
                pushSnapshot();
                return;
            }
        }
    }

    if (!s19Packet.isHurt()) { return; }

    int hurtEntityId = s19Packet.entityId();
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }

    if (myEntityId_ == -1) { return; }

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    EntityClientPlayerMP thePlayer = mc.thePlayer();
    if (thePlayer.isNull()) return;

    WorldClient world = mc.theWorld();
    if (world.isNull()) return;

    if (hurtEntityId != myEntityId_) {
        ArrayList playerList = world.playerEntities();
        if (playerList.isNull()) { return; }
        bool inRadius = false;
        int count = playerList.size();
        for (int i = 0; i < count; i++) {
            JavaObject obj = playerList.get(i);
            if (obj.isNull()) continue;
            Entity entity(env, obj.getObj());
            entity.setDeleteRef(false);
            if (entity.isNull()) continue;
            if (entity.entityId() == hurtEntityId) {
                float dist = thePlayer.getDistanceToEntity(entity);
                inRadius = (dist <= radius);
                break;
            }
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (!inRadius) { return; }
    }

    bool hurtEntityIsFriendOrMe = (hurtEntityId == myEntityId_) || isFriendOrMe(env, hurtEntityId);

    bool iHitThem = wasMyAttack(hurtEntityId);

    if (mode == 0) {
        if (hurtEntityId == myEntityId_) {
            if (pearlInFlight_) {
                pearlInFlight_ = false;
            } else {
                enemyHits_++;
            }
        } else if (!hurtEntityIsFriendOrMe) {

            if (targetEntityId_ == -1) {
                targetEntityId_ = hurtEntityId;
            }
            if (hurtEntityId == targetEntityId_) {
                myHits_++;
            }
        }
    } else {
        if (hurtEntityIsFriendOrMe) {
            enemyTeamHits_++;
        } else if (iHitThem) {
            teamHits_++;
        }
    }

    if (env->ExceptionCheck()) env->ExceptionClear();
}

void HitHealCounterModule::onTick(const OnRunTickEvent& event) {
    if (!this->enable) return;

    JNIEnv* env = event.getEnv();
    if (!env) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    EntityClientPlayerMP thePlayer = mc.thePlayer();
    if (thePlayer.isNull()) return;

    myEntityId_ = thePlayer.entityId();
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }

    {
        WorldClient world = mc.theWorld();
        if (!world.isNull()) {
            ArrayList playerList = world.playerEntities();
            if (!playerList.isNull()) {
                int count = playerList.size();
                bool targetFound = false;
                bool anyEnemyInRange = false;

                for (int i = 0; i < count; i++) {
                    if (env->ExceptionCheck()) { env->ExceptionClear(); break; }
                    JavaObject playerObj = playerList.get(i);
                    if (playerObj.isNull()) continue;

                    Entity entity(env, playerObj.getObj());
                    entity.setDeleteRef(false);
                    if (entity.isNull() || !entity.isPlayer()) continue;

                    int eid = entity.entityId();
                    if (eid == myEntityId_) continue;

                    float dist = thePlayer.getDistanceToEntity(entity);
                    if (dist > radius) continue;

                    bool isFriend = FriendsModule::getInstance().isFriend(entity);

                    if (mode == 0) {

                        if (targetEntityId_ != -1 && eid == targetEntityId_) {
                            targetFound = true;
                            targetOutOfRangeSince_ = 0;
                        }

                        if (targetEntityId_ == -1 && !isFriend) {
                            targetEntityId_ = eid;
                            targetOutOfRangeSince_ = 0;
                            jstring name = nullptr;
                            if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
                                name = entity.getName();
                            }
                            if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
                                name = entity.getCommandSenderName();
                            }
                            if (name) {
                                targetName_ = JavaString::jstringToString(env, name);
                                env->DeleteLocalRef(name);
                            }
                            if (env->ExceptionCheck()) env->ExceptionClear();
                            targetFound = true;
                        }
                    } else {

                        if (!isFriend) {
                            anyEnemyInRange = true;
                        }
                    }
                }

                long long now = nowMs();

                if (mode == 0) {

                    if (targetEntityId_ != -1 && !targetFound) {
                        if (targetOutOfRangeSince_ == 0) {
                            targetOutOfRangeSince_ = now;
                        } else if ((now - targetOutOfRangeSince_) >= OUT_OF_RANGE_RESET_MS) {
                                        resetCounters();
                        }
                    }
                } else {

                    bool hadActivity = (teamHits_ > 0 || teamPots_ > 0 || enemyTeamHits_ > 0 || enemyTeamPots_ > 0);
                    if (hadActivity && !anyEnemyInRange) {
                        if (noEnemiesInRangeSince_ == 0) {
                            noEnemiesInRangeSince_ = now;
                        } else if ((now - noEnemiesInRangeSince_) >= OUT_OF_RANGE_RESET_MS) {
                                        resetCounters();
                        }
                    } else if (anyEnemyInRange) {
                        noEnemiesInRangeSince_ = 0;
                    }
                }
            }
        }
    }

    if (env->ExceptionCheck()) env->ExceptionClear();

    pushSnapshot();
}

void HitHealCounterModule::pushSnapshot() {
    RenderSnapshot s{};
    s.mode           = mode;
    s.myHits         = myHits_;
    s.myPots         = myPots_;
    s.enemyHits      = enemyHits_;
    s.enemyPots      = enemyPots_;
    s.teamHits       = teamHits_;
    s.teamPots       = teamPots_;
    s.enemyTeamHits  = enemyTeamHits_;
    s.enemyTeamPots  = enemyTeamPots_;
    s.hasTarget      = targetEntityId_ != -1 && !targetName_.empty();
    if (s.hasTarget)
        snprintf(s.targetName, sizeof(s.targetName), "%s", targetName_.c_str());

    std::lock_guard<std::mutex> lock(snapMutex_);
    snap_ = s;
}

void HitHealCounterModule::onRender2d(const Render2dEvent& event) {
    if (!this->enable) return;

    ImDrawList* drawList = ImGui::GetBackgroundDrawList();
    if (!drawList) return;

    const ImGuiIO& io = ImGui::GetIO();
    const float sw = io.DisplaySize.x;
    const float sh = io.DisplaySize.y;

    ImFont* font = ImGui::GetFont();
    if (!font) return;

    RenderSnapshot snap;
    { std::lock_guard<std::mutex> lock(snapMutex_); snap = snap_; }

    if (currentScale_ < 0.0f) currentScale_ = scale;
    const float dt = io.DeltaTime;
    currentScale_ += (scale - currentScale_) * (1.0f - expf(-18.0f * dt));
    if (fabsf(currentScale_ - scale) < 0.001f) currentScale_ = scale;
    const float s = currentScale_;

    const float FONT_SZ     = 10.0f * s;
    const float FONT_SM     = 8.5f  * s;
    const float PAD_X       = 10.0f * s;
    const float PAD_Y       = 5.0f  * s;
    const float ROW_H       = 12.0f * s;
    const float SECTION_GAP = 5.0f  * s;
    const float ROUNDING    = 4.0f  * s;

    const ImU32 cAccent = draw->get_clr(ImVec4(clr->accent.Value.x, clr->accent.Value.y, clr->accent.Value.z, 1.0f));
    const ImU32 cWhite  = draw->get_clr(ImVec4(1, 1, 1, 0.90f));
    const ImU32 cDim    = draw->get_clr(ImVec4(1, 1, 1, 0.45f));
    const ImU32 cDot    = draw->get_clr(ImVec4(1, 1, 1, 0.20f));
    const ImU32 cShadow = draw->get_clr(ImVec4(0, 0, 0, 0.45f));

    struct Row { int type; const char* label; int value; ImU32 labelColor; ImU32 valueColor; };
    char headerBuf[32], targetBuf[64], potDiffBuf[32];
    std::vector<Row> rows;
    rows.reserve(16);

    const ImU32 cGreen = draw->get_clr(ImVec4(0.2f, 1.0f, 0.4f, 0.95f));
    const ImU32 cRed   = draw->get_clr(ImVec4(1.0f, 0.3f, 0.3f, 0.95f));

    char hitDiffBuf[32];

    if (snap.mode == 0) {
        int hitDiff = snap.myHits - snap.enemyHits;
        int potDiff = snap.enemyPots - snap.myPots;

        snprintf(headerBuf, sizeof(headerBuf), "Counters · Solo");
        rows.push_back({ 0, headerBuf, 0, cAccent, 0 });
        rows.push_back({ 2, nullptr, 0, 0, 0 });

        if (hitDiff > 0) snprintf(hitDiffBuf, sizeof(hitDiffBuf), "+%d", hitDiff);
        else if (hitDiff < 0) snprintf(hitDiffBuf, sizeof(hitDiffBuf), "%d", hitDiff);
        else snprintf(hitDiffBuf, sizeof(hitDiffBuf), "0");
        rows.push_back({ 5, hitDiffBuf, hitDiff, 0, hitDiff > 0 ? cGreen : (hitDiff < 0 ? cRed : cDim) });

        if (potDiff > 0) snprintf(potDiffBuf, sizeof(potDiffBuf), "+%d", potDiff);
        else if (potDiff < 0) snprintf(potDiffBuf, sizeof(potDiffBuf), "%d", potDiff);
        else snprintf(potDiffBuf, sizeof(potDiffBuf), "0");
        rows.push_back({ 4, potDiffBuf, potDiff, 0, potDiff > 0 ? cGreen : (potDiff < 0 ? cRed : cDim) });

        rows.push_back({ 2, nullptr, 0, 0, 0 });

        if (snap.hasTarget) {
            snprintf(targetBuf, sizeof(targetBuf), "%s", snap.targetName);
            rows.push_back({ 3, targetBuf, 0, cWhite, 0 });
        } else {
            rows.push_back({ 3, "Enemy", 0, cWhite, 0 });
        }
        rows.push_back({ 1, "Hits",  snap.enemyHits,  cDim, cWhite });
        rows.push_back({ 1, "Pots",  snap.enemyPots,  cDim, cAccent });

        rows.push_back({ 3, "You", 0, cWhite, 0 });
        rows.push_back({ 1, "Hits",  snap.myHits,  cDim, cWhite });
        rows.push_back({ 1, "Pots",  snap.myPots,  cDim, cAccent });
    } else {
        int hitDiff = snap.teamHits - snap.enemyTeamHits;
        int potDiff = snap.enemyTeamPots - snap.teamPots;

        snprintf(headerBuf, sizeof(headerBuf), "Counters · Team");
        rows.push_back({ 0, headerBuf, 0, cAccent, 0 });
        rows.push_back({ 2, nullptr, 0, 0, 0 });

        if (hitDiff > 0) snprintf(hitDiffBuf, sizeof(hitDiffBuf), "+%d", hitDiff);
        else if (hitDiff < 0) snprintf(hitDiffBuf, sizeof(hitDiffBuf), "%d", hitDiff);
        else snprintf(hitDiffBuf, sizeof(hitDiffBuf), "0");
        rows.push_back({ 5, hitDiffBuf, hitDiff, 0, hitDiff > 0 ? cGreen : (hitDiff < 0 ? cRed : cDim) });

        if (potDiff > 0) snprintf(potDiffBuf, sizeof(potDiffBuf), "+%d", potDiff);
        else if (potDiff < 0) snprintf(potDiffBuf, sizeof(potDiffBuf), "%d", potDiff);
        else snprintf(potDiffBuf, sizeof(potDiffBuf), "0");
        rows.push_back({ 4, potDiffBuf, potDiff, 0, potDiff > 0 ? cGreen : (potDiff < 0 ? cRed : cDim) });

        rows.push_back({ 2, nullptr, 0, 0, 0 });

        rows.push_back({ 3, "Enemies", 0, cWhite, 0 });
        rows.push_back({ 1, "Hits",  snap.enemyTeamHits,  cDim, cWhite });
        rows.push_back({ 1, "Pots",  snap.enemyTeamPots,  cDim, cAccent });

        rows.push_back({ 3, "My Team", 0, cWhite, 0 });
        rows.push_back({ 1, "Hits",  snap.teamHits,  cDim, cWhite });
        rows.push_back({ 1, "Pots",  snap.teamPots,  cDim, cAccent });
    }

    float contentW = 0.0f, contentH = 0.0f;
    for (const auto& r : rows) {
        switch (r.type) {
            case 0: {
                float w = font->CalcTextSizeA(FONT_SZ, FLT_MAX, 0, r.label).x;
                if (w > contentW) contentW = w;
                contentH += ROW_H + 1.0f * s;
                break;
            }
            case 1: {
                char vb[16]; snprintf(vb, sizeof(vb), "%d", r.value);
                float rw = font->CalcTextSizeA(FONT_SM, FLT_MAX, 0, r.label).x
                         + 20.0f * s
                         + font->CalcTextSizeA(FONT_SM, FLT_MAX, 0, vb).x;
                if (rw > contentW) contentW = rw;
                contentH += ROW_H;
                break;
            }
            case 2: contentH += SECTION_GAP; break;
            case 3: {
                float w = font->CalcTextSizeA(FONT_SM, FLT_MAX, 0, r.label).x;
                if (w > contentW) contentW = w;
                contentH += ROW_H;
                break;
            }
            case 4: {
                float lw = font->CalcTextSizeA(FONT_SM, FLT_MAX, 0, "Pot Diff").x;
                float vw = font->CalcTextSizeA(FONT_SM, FLT_MAX, 0, r.label).x;
                float rw = lw + 20.0f * s + vw;
                if (rw > contentW) contentW = rw;
                contentH += ROW_H;
                break;
            }
            case 5: {
                float lw = font->CalcTextSizeA(FONT_SM, FLT_MAX, 0, "Hit Diff").x;
                float vw = font->CalcTextSizeA(FONT_SM, FLT_MAX, 0, r.label).x;
                float rw = lw + 20.0f * s + vw;
                if (rw > contentW) contentW = rw;
                contentH += ROW_H;
                break;
            }
        }
    }

    const float barW = contentW + PAD_X * 2.0f;
    const float barH = contentH + PAD_Y * 2.0f;

    float barX = ImFloor(posNX * sw);
    float barY = ImFloor(posNY * sh);
    barX = ImFloor(std::max(0.0f, std::min(barX, sw - barW)));
    barY = ImFloor(std::max(0.0f, std::min(barY, sh - barH)));

    if (Gui::getInstance().isOpen() && !io.WantCaptureMouse) {
        const ImVec2 mouse = ImGui::GetMousePos();
        const bool down = ImGui::IsMouseDown(0);
        const bool clicked = ImGui::IsMouseClicked(0);
        const ImRect rect(ImVec2(barX, barY), ImVec2(barX + barW, barY + barH));

        constexpr float HANDLE_SZ = 10.0f;
        const ImRect resizeRect(
            ImVec2(barX + barW - HANDLE_SZ, barY + barH - HANDLE_SZ),
            ImVec2(barX + barW, barY + barH));

        if (clicked) {
            if (resizeRect.Contains(mouse)) {
                resizing_ = true;
                resizeBaseScale_ = scale;
                resizeBaseMouseX_ = mouse.x;
                dragging_ = false;
            } else if (rect.Contains(mouse)) {
                dragging_ = true;
                dragOffset_ = ImVec2(barX - mouse.x, barY - mouse.y);
                resizing_ = false;
            } else {
                dragging_ = false;
                resizing_ = false;
            }
        }

        if (resizing_) {
            if (down) {
                float delta = (mouse.x - resizeBaseMouseX_) * 0.01f;
                scale = std::clamp(resizeBaseScale_ + delta, 0.5f, 3.0f);
            } else {
                resizing_ = false;
            }
        }

        if (dragging_) {
            if (down) {
                float nx = std::max(0.0f, std::min(mouse.x + dragOffset_.x, sw - barW));
                float ny = std::max(0.0f, std::min(mouse.y + dragOffset_.y, sh - barH));
                posNX = nx / sw; posNY = ny / sh;
                barX = nx; barY = ny;
            } else { dragging_ = false; }
        }
    }

    const ImVec2 bgMin(barX, barY), bgMax(barX + barW, barY + barH);

    drawList->PushClipRect(ImVec2(0, 0), ImVec2(sw, sh), true);
    draw->shadow_rect(drawList, bgMin, bgMax,
        draw->get_clr(ImVec4(0, 0, 0, 0.60f)), 3.0f, ImVec2(0, 1), 0, ROUNDING);
    drawList->PopClipRect();

    if (blurEnabled) {
        static KawaseBlur::BlurParams bp;
        bp.strength = 1.0f; bp.cornerRadius = ROUNDING;
        bp.rect = { bgMin.x, bgMin.y, bgMax.x, bgMax.y };
        bp.tint = { clr->child.Value.x, clr->child.Value.y, clr->child.Value.z, blurOpacity };
        drawList->AddCallback(KawaseBlur::renderDrawListBlur, &bp);
        drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
    }

    draw->rect_filled(drawList, bgMin, bgMax,
        draw->get_clr(ImVec4(clr->child.Value.x, clr->child.Value.y, clr->child.Value.z,
            blurEnabled ? 0.0f : blurOpacity)),
        ROUNDING, draw_flags_round_corners_all);

    draw->rect(drawList, bgMin, bgMax,
        draw->get_clr(ImVec4(clr->accent.Value.x, clr->accent.Value.y, clr->accent.Value.z, 0.12f)),
        ROUNDING, draw_flags_round_corners_all, 1.0f);

    draw->rect_filled(drawList,
        ImVec2(bgMin.x, bgMin.y + ROUNDING),
        ImVec2(bgMin.x + 2.0f * s, bgMax.y - ROUNDING),
        draw->get_clr(ImVec4(clr->accent.Value.x, clr->accent.Value.y, clr->accent.Value.z, 0.80f)),
        0.0f, 0);

    float cy = ImFloor(barY + PAD_Y);
    const float leftX  = ImFloor(barX + PAD_X);
    const float rightX = ImFloor(barX + barW - PAD_X);

    for (const auto& r : rows) {
        switch (r.type) {
            case 0:
                drawList->AddText(font, FONT_SZ, ImVec2(leftX, cy + 1), cShadow, r.label);
                drawList->AddText(font, FONT_SZ, ImVec2(leftX, cy), r.labelColor, r.label);
                cy += ROW_H + 1.0f * s;
                break;
            case 1: {
                char vb[16]; snprintf(vb, sizeof(vb), "%d", r.value);
                float valW = font->CalcTextSizeA(FONT_SM, FLT_MAX, 0, vb).x;
                float valX = ImFloor(rightX - valW);
                drawList->AddText(font, FONT_SM, ImVec2(leftX, cy + 1), cShadow, r.label);
                drawList->AddText(font, FONT_SM, ImVec2(leftX, cy), r.labelColor, r.label);
                drawList->AddText(font, FONT_SM, ImVec2(valX, cy + 1), cShadow, vb);
                drawList->AddText(font, FONT_SM, ImVec2(valX, cy), r.valueColor, vb);
                cy += ROW_H;
                break;
            }
            case 2: {
                float sepY = ImFloor(cy + SECTION_GAP * 0.5f);
                drawList->AddLine(ImVec2(leftX, sepY), ImVec2(rightX, sepY), cDot, 1.0f);
                cy += SECTION_GAP;
                break;
            }
            case 3:
                drawList->AddText(font, FONT_SM, ImVec2(leftX, cy + 1), cShadow, r.label);
                drawList->AddText(font, FONT_SM, ImVec2(leftX, cy), r.labelColor, r.label);
                cy += ROW_H;
                break;
            case 4: {
                const char* diffLabel = "Pot Diff";
                float valW = font->CalcTextSizeA(FONT_SM, FLT_MAX, 0, r.label).x;
                float valX = ImFloor(rightX - valW);
                drawList->AddText(font, FONT_SM, ImVec2(leftX, cy + 1), cShadow, diffLabel);
                drawList->AddText(font, FONT_SM, ImVec2(leftX, cy), cDim, diffLabel);
                drawList->AddText(font, FONT_SM, ImVec2(valX, cy + 1), cShadow, r.label);
                drawList->AddText(font, FONT_SM, ImVec2(valX, cy), r.valueColor, r.label);
                cy += ROW_H;
                break;
            }
            case 5: {
                const char* diffLabel = "Hit Diff";
                float valW = font->CalcTextSizeA(FONT_SM, FLT_MAX, 0, r.label).x;
                float valX = ImFloor(rightX - valW);
                drawList->AddText(font, FONT_SM, ImVec2(leftX, cy + 1), cShadow, diffLabel);
                drawList->AddText(font, FONT_SM, ImVec2(leftX, cy), cDim, diffLabel);
                drawList->AddText(font, FONT_SM, ImVec2(valX, cy + 1), cShadow, r.label);
                drawList->AddText(font, FONT_SM, ImVec2(valX, cy), r.valueColor, r.label);
                cy += ROW_H;
                break;
            }
        }
    }

    if (Gui::getInstance().isOpen()) {
        const ImU32 col = (dragging_ || resizing_)
            ? IM_COL32(255, 165, 0, 220) : IM_COL32(100, 180, 255, 180);
        drawList->AddRect(
            ImVec2(bgMin.x - 2, bgMin.y - 2), ImVec2(bgMax.x + 2, bgMax.y + 2),
            col, ROUNDING + 2, 0, 1.5f);

        const ImU32 handleCol = resizing_ ? IM_COL32(255, 165, 0, 255) : IM_COL32(100, 180, 255, 220);
        drawList->AddTriangleFilled(
            ImVec2(bgMax.x, bgMax.y),
            ImVec2(bgMax.x - 10.0f, bgMax.y),
            ImVec2(bgMax.x, bgMax.y - 10.0f),
            handleCol);
    }
}

void HitHealCounterModule::resetCounters() {
    myHits_ = myPots_ = 0;
    enemyHits_ = enemyPots_ = 0;
    teamHits_ = teamPots_ = 0;
    enemyTeamHits_ = enemyTeamPots_ = 0;
    targetEntityId_ = -1;
    targetName_.clear();
    targetOutOfRangeSince_ = 0;
    noEnemiesInRangeSince_ = 0;
    pendingAttacks_.clear();
}

REGISTER_MODULE(HitHealCounterModule, ModuleType::HIT_HEAL_COUNTER)
