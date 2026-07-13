#include "../../../../includes/module/impl/network/BlinkModule.h"
#include "../../../../includes/wrapper/minecraft/client/Minecraft.h"
#include "../../../../includes/wrapper/minecraft/client/network/NetHandlerPlayClient.h"
#include "../../../../includes/wrapper/minecraft/network/NetworkManager.h"
#include "../../../../includes/wrapper/minecraft/entity/EntityLivingBase.h"
#include "../../../../includes/wrapper/minecraft/entity/render/RenderManager.h"
#include "../../../../includes/wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo2.h"
#include "../../../../includes/wrapper/CVarsUpdater.h"
#include "../../../../includes/handler/MappingHandler.h"
#include "../../../../includes/util/RenderUtils.h"

#include "setting/SettingMacros.h"
#include "includes.h"
#include "Poppins-Bold.h"
#include "imgui_freetype.h"
#include "imgui_impl_opengl2.h"
#include "util/KawaseBlur.h"

#include <GL/gl.h>

jclass BlinkModule::C03PacketPlayerClass_ = nullptr;
jclass BlinkModule::C00PacketKeepAliveClass_ = nullptr;
jclass BlinkModule::C0FPacketConfirmTransactionClass_ = nullptr;
jclass BlinkModule::S00PacketKeepAliveClass_ = nullptr;
jclass BlinkModule::S32PacketConfirmTransactionClass_ = nullptr;
jclass BlinkModule::C02PacketUseEntityClass_ = nullptr;
jclass BlinkModule::S06PacketUpdateHealthClass_ = nullptr;

void BlinkModule::forceDisable() {
    doBlink_ = false;
    fired_   = true;
    setEnabled(false);
}

void BlinkModule::onLoad() {
    ListenedBaseModule::onLoad();

    COMBO_SETTING(direction, "OutBound", "InBound", "Both");
    INT_SLIDER(autoSendDelay, 5000, 0, 20000);
    BOOL_SETTING_CONDITIONAL(disableOnLocalDamage, false);
    BOOL_SETTING_CONDITIONAL(disableOnTargetDamage, false);
    BOOL_SETTING_CONDITIONAL(drawEsp, true);
    COLOR_SETTING_CONDITIONAL_OPTIONAL(espColor, ImColor(0.08f, 0.47f, 0.90f, 0.55f), SETTING_VISIBILITY(drawEsp));
}

void BlinkModule::onEnable() {
    ListenedBaseModule::onEnable();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        sendQueue_.clear();
        receiveQueue_.clear();
    }

    timer_           = getCurrentTime();
    doBlink_         = true;
    fired_           = false;
    pendingDisable_  = false;
    hasBlinkPos_     = false;
}

void BlinkModule::onDisable() {
    doBlink_ = false;
    hasBlinkPos_ = false;

    JNIEnv* env = nullptr;
    bool attached = false;
    JavaVM* jvm = nullptr;
    if (JNI_GetCreatedJavaVMs(&jvm, 1, nullptr) == JNI_OK && jvm) {
        jint result = jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
        if (result == JNI_EDETACHED) {
            if (jvm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) == JNI_OK)
                attached = true;
        }
    }

    if (env) {
        releasePackets(env);
    } else {
        std::lock_guard<std::mutex> lock(mutex_);
        sendQueue_.clear();
        receiveQueue_.clear();
    }

    if (attached && jvm) jvm->DetachCurrentThread();

}

void BlinkModule::registerEvents() {
    subscribe<AddSendQueueEvent>([this](const AddSendQueueEvent& event) {
        onPacketSend(event);
    }, EventPriority::HIGH, false);

    subscribe<ChannelReadEvent>([this](const ChannelReadEvent& event) {
        onPacketReceive(event);
    }, EventPriority::HIGH, false);

    subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
        onTick(event);
    });

    subscribe<PlayerAttackEvent>([this](const PlayerAttackEvent& event) {
        onPlayerAttack(event);
    });

    subscribe<Render2dEvent>([this](const Render2dEvent& event) {
        onRender2d(event);
    });

    subscribe<Render3dEvent>([this](const Render3dEvent& event) {
        onRender3d(event);
    });
}

void BlinkModule::onPacketSend(const AddSendQueueEvent& event) {
    if (!this->enable) return;

    JNIEnv* env = event.getEnv();
    jobject packet = event.getPacketObject();
    if (!env || !packet) return;

    if (isConnectionPacket(env, packet)) return;

    if (direction != 0 && direction != 2) return;

    if (!doBlink_) return;

    if (!isMovementPacket(env, packet)) return;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        BlinkSendData data;
        data.packet = env->NewGlobalRef(packet);
        sendQueue_.push_back(data);
    }

    const_cast<AddSendQueueEvent&>(event).setCancelled(true);
}

void BlinkModule::onPacketReceive(const ChannelReadEvent& event) {
    if (!this->enable) return;

    JNIEnv* env = event.getEnv();
    jobject packet = event.getPacketObject();
    if (!env || !packet) return;

    if (isConnectionPacket(env, packet)) return;

    if (disableOnLocalDamage && isInstanceOf(env, packet, S06PacketUpdateHealthClass_, "S06PacketUpdateHealth")) {
        pendingDisable_ = true;
        return;
    }

    if (direction != 1 && direction != 2) return;

    if (!doBlink_) return;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        BlinkReceiveData data;
        data.packet = env->NewGlobalRef(packet);
        receiveQueue_.push_back(data);
    }

    const_cast<ChannelReadEvent&>(event).setCancelled(true);
}

void BlinkModule::onTick(const OnRunTickEvent& event) {
    if (!this->enable) return;

    if (pendingDisable_.exchange(false)) {
        setEnabled(false);
        return;
    }

    if (fired_) return;

    JNIEnv* env = event.getEnv();
    if (!env) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    auto player = mc.thePlayer();
    if (player.isNull()) return;

    if (!hasBlinkPos_) {
        blinkStartX_ = player.posX();
        blinkStartY_ = player.posY();
        blinkStartZ_ = player.posZ();

        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
            blinkStartY_ -= 1.62;
        }
        hasBlinkPos_ = true;
    }

    if (disableOnLocalDamage) {
        EntityLivingBase living(env, player.getObj());
        living.setDeleteRef(false);
        if (living.hurtTime() > 0) {
            pendingDisable_ = true;
            return;
        }
    }

    if (disableOnTargetDamage) {
        EntityLivingBase living2(env, player.getObj());
        living2.setDeleteRef(false);
        if (living2.isSwingInProgress()) {
            pendingDisable_ = true;
            return;
        }
    }

    if (autoSendDelay <= 0) return;

    long long currentTime = getCurrentTime();
    if (currentTime - timer_ >= autoSendDelay) {
        releasePackets(env);
        doBlink_ = false;
        fired_   = true;
        setEnabled(false);
    }
}

void BlinkModule::onPlayerAttack(const PlayerAttackEvent& event) {
    (void)event;
}

void BlinkModule::onRender3d(const Render3dEvent& event) {
    if (!this->enable || !drawEsp || !hasBlinkPos_ || fired_) return;

    JNIEnv* env = event.getEnv();
    if (!env) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    bool is18 = MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9;

    Vec3D renderPos;
    if (is18) {
        RenderManager rm = mc.getRenderManager();
        if (rm.isNull()) return;
        renderPos = rm.getRenderPos();
        env->DeleteLocalRef(rm.getObj());
    } else {
        RenderManager rm = RenderManager::getInstance(env);
        if (rm.isNull()) return;
        renderPos = rm.getRenderPos();
        env->DeleteLocalRef(rm.getObj());
    }

    float x = static_cast<float>(blinkStartX_ - renderPos.x);
    float y = static_cast<float>(blinkStartY_ - renderPos.y);
    float z = static_cast<float>(blinkStartZ_ - renderPos.z);

    Vector3f minPos(x - 0.3f, y, z - 0.3f);
    Vector3f maxPos(x + 0.3f, y + 1.8f, z + 0.3f);

    auto activeRenderInfo = ActiveRenderInfo2::getInstance(env);
    if (!activeRenderInfo.isNull()) {
        activeRenderInfo.getModelView(CVarsUpdater::ModelView);
        activeRenderInfo.getProjection(CVarsUpdater::Projection);
    }

    // Balance each matrix stack explicitly: CheatBreaker leaves GL_PROJECTION active on entry
    // (stack only 2 deep), so a bare glPushMatrix() overflows it after ~2 frames and corrupts
    // rendering. Save/restore both stacks instead of clobbering the projection. See LagRangeModule.
    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    glLoadMatrixd(CVarsUpdater::Projection.data());
    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();
    glLoadMatrixd(CVarsUpdater::ModelView.data());

    RenderUtils::setupRenderState(2.0f);

    Color outlineCol(espColor.Value.x, espColor.Value.y, espColor.Value.z, espColor.Value.w);
    Color fillCol(espColor.Value.x, espColor.Value.y, espColor.Value.z, espColor.Value.w * 0.3f);

    RenderUtils::drawBoxLines(minPos, maxPos, outlineCol);
    RenderUtils::drawBoxFilled(minPos, maxPos, fillCol);

    RenderUtils::restoreRenderState();
    glMatrixMode(GL_PROJECTION);
    glPopMatrix();
    glMatrixMode(GL_MODELVIEW);
    glPopMatrix();
}

void BlinkModule::releasePackets(JNIEnv* env) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (sendQueue_.empty() && receiveQueue_.empty()) return;

    if (!sendQueue_.empty()) {
        Minecraft mc = Minecraft::getMinecraft(env);
        if (!mc.isNull()) {
            NetHandlerPlayClient netHandler = mc.getNetHandler();
            if (!netHandler.isNull()) {
                NetworkManager netManager = netHandler.getNetworkManager();
                if (!netManager.isNull()) {
                    for (auto& data : sendQueue_) {
                        if (data.packet && !env->IsSameObject(data.packet, nullptr)) {
                            netManager.dispatchPacket(data.packet);
                        }
                        if (data.packet) env->DeleteGlobalRef(data.packet);
                    }
                } else {
                    for (auto& data : sendQueue_) {
                        if (data.packet) env->DeleteGlobalRef(data.packet);
                    }
                }
            } else {
                for (auto& data : sendQueue_) {
                    if (data.packet) env->DeleteGlobalRef(data.packet);
                }
            }
        } else {
            for (auto& data : sendQueue_) {
                if (data.packet) env->DeleteGlobalRef(data.packet);
            }
        }
        sendQueue_.clear();
    }

    if (!receiveQueue_.empty()) {
        cacheProcessPacketMethod(env);

        Minecraft mc = Minecraft::getMinecraft(env);
        if (!mc.isNull() && processPacketCached_) {
            NetHandlerPlayClient netHandler = mc.getNetHandler();
            if (!netHandler.isNull()) {
                for (auto& data : receiveQueue_) {
                    if (data.packet && !env->IsSameObject(data.packet, nullptr)) {
                        env->CallVoidMethod(data.packet, processPacketMethod_, netHandler.getObj());
                        if (env->ExceptionCheck()) {
                            env->ExceptionClear();
                        }
                    }
                    if (data.packet) env->DeleteGlobalRef(data.packet);
                }
            } else {
                for (auto& data : receiveQueue_) {
                    if (data.packet) env->DeleteGlobalRef(data.packet);
                }
            }
        } else {
            for (auto& data : receiveQueue_) {
                if (data.packet) env->DeleteGlobalRef(data.packet);
            }
        }
        receiveQueue_.clear();
    }
}

void BlinkModule::clearQueues(JNIEnv* env) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& data : sendQueue_) {
        if (env && data.packet) env->DeleteGlobalRef(data.packet);
    }
    sendQueue_.clear();

    for (auto& data : receiveQueue_) {
        if (env && data.packet) env->DeleteGlobalRef(data.packet);
    }
    receiveQueue_.clear();
}

bool BlinkModule::isConnectionPacket(JNIEnv* env, jobject packet) {
    if (isInstanceOf(env, packet, C00PacketKeepAliveClass_, "C00PacketKeepAlive")) return true;
    if (isInstanceOf(env, packet, C0FPacketConfirmTransactionClass_, "C0FPacketConfirmTransaction")) return true;
    if (isInstanceOf(env, packet, S00PacketKeepAliveClass_, "S00PacketKeepAlive")) return true;
    if (isInstanceOf(env, packet, S32PacketConfirmTransactionClass_, "S32PacketConfirmTransaction")) return true;
    return false;
}

bool BlinkModule::isMovementPacket(JNIEnv* env, jobject packet) {

    return isInstanceOf(env, packet, C03PacketPlayerClass_, "C03PacketPlayer");
}

void BlinkModule::cacheProcessPacketMethod(JNIEnv* env) {
    if (processPacketCached_ || !env) return;

    processPacketMethod_ = Mappings::getInstance().getMethod("Packet#processPacket");
    processPacketCached_ = processPacketMethod_ != nullptr;
}

bool BlinkModule::isInstanceOf(JNIEnv* env, jobject obj, jclass& cached, const char* className) {
    if (!cached) {
        cached = Mappings::getInstance().getClass(className);
    }
    return cached && env->IsInstanceOf(obj, cached);
}

void BlinkModule::initFont() {
    if (fontInitialized_) return;

    ImGuiIO& io = ImGui::GetIO();
    ImFontConfig cfg;
    cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_MonoHinting | ImGuiFreeTypeBuilderFlags_Monochrome;
    cfg.FontDataOwnedByAtlas = false;

    blinkFont_ = io.Fonts->AddFontFromMemoryTTF(
        const_cast<void*>(static_cast<const void*>(Poppins_Bold_compressed_data.data())),
        static_cast<int>(Poppins_Bold_compressed_data.size()),
        11.0f, &cfg,
        io.Fonts->GetGlyphRangesCyrillic()
    );

    io.Fonts->Build();
    ImGui_ImplOpenGL2_DestroyFontsTexture();
    ImGui_ImplOpenGL2_CreateFontsTexture();

    fontInitialized_ = blinkFont_ != nullptr;
}

void BlinkModule::onRender2d(const Render2dEvent& event) {
    if (!this->enable) return;
    if (fired_) return;
    if (autoSendDelay <= 0) return;

    ImDrawList* drawList = ImGui::GetBackgroundDrawList();
    if (!drawList) return;

    const ImGuiIO& io = ImGui::GetIO();
    const float screenW = io.DisplaySize.x;

    long long now = getCurrentTime();
    float remaining = 1.0f - static_cast<float>(now - timer_) / static_cast<float>(autoSendDelay);
    if (remaining < 0.0f) remaining = 0.0f;
    if (remaining > 1.0f) remaining = 1.0f;

    constexpr float BAR_W    = 560.0f;
    constexpr float BAR_H    = 18.0f;
    constexpr float BAR_Y    = 0.0f;
    constexpr float ROUNDING = 4.0f;

    constexpr ImVec4 blue(0.25f, 0.52f, 1.00f, 1.0f);

    const float barX = (screenW - BAR_W) * 0.5f;
    const ImVec2 bgMin(barX, BAR_Y);
    const ImVec2 bgMax(barX + BAR_W, BAR_Y + BAR_H);

    draw->rect_filled(drawList, bgMin, bgMax,
        draw->get_clr(ImVec4(1.0f, 1.0f, 1.0f, 0.12f)),
        ROUNDING, draw_flags_round_corners_all);

    if (remaining > 0.001f) {
        const float fillW = BAR_W * remaining;
        const ImVec2 fillMax(barX + fillW, BAR_Y + BAR_H);
        const draw_flags fillFlags = (remaining >= 0.999f)
            ? draw_flags_round_corners_all
            : draw_flags_round_corners_left;

        draw->shadow_rect(drawList, bgMin, fillMax,
            draw->get_clr(ImVec4(blue.x, blue.y, blue.z, 0.55f)),
            12.0f, ImVec2(0.0f, 0.0f), 0, ROUNDING);

        draw->rect_filled(drawList, bgMin, fillMax,
            draw->get_clr(ImVec4(blue.x, blue.y, blue.z, 1.0f)),
            ROUNDING, fillFlags);

        draw->rect_filled(drawList,
            ImVec2(barX + ROUNDING, BAR_Y + 0.5f),
            ImVec2(barX + fillW - (remaining >= 0.999f ? ROUNDING : 0.5f), BAR_Y + 1.5f),
            draw->get_clr(ImVec4(1.0f, 1.0f, 1.0f, 0.35f)),
            0.5f, 0);
    }
}

REGISTER_MODULE(BlinkModule, ModuleType::BLINK)
