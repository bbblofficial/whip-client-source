#pragma once

#include "../IProvider.h"
#include <queue>
#include <vector>
#include <chrono>
#include <mutex>

#include "provider/base/BaseProvider.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/primitive/JavaObject.h"

struct QueuedPacket {
    jobject packet;
    long long timestamp;

    QueuedPacket(jobject pkt, long long ts)
        : packet(pkt), timestamp(ts) {}
};

class PacketProvider final : public BaseProvider<PacketProvider, ProviderType::PACKET>{
    std::queue<QueuedPacket> packetQueue_;
    mutable std::mutex queueMutex_;
    int delayMs_ = 200;

    std::queue<QueuedPacket> outboundQueue_;
    mutable std::mutex outboundMutex_;
    int outboundDelayMs_ = 200;

    bool enabled_ = false;

    jmethodID processPacketMethod_ = nullptr;
    bool methodCached_ = false;

public:
    PacketProvider() { }
    ~PacketProvider() override { }

    ProviderType getType() const override {
        return ProviderType::PACKET;
    }

    [[nodiscard]] bool isEnabled() const override {
        return enabled_;
    }

    void setEnabled(const bool enable) override {
        enabled_ = enable;
    }

    void onEnable() override {}
    void onDisable() override {}

    void queuePacket(JNIEnv* env, jobject packet) {
        if (!env || !packet) return;

        jobject globalPkt = env->NewGlobalRef(packet);
        if (!globalPkt) return;

        std::lock_guard lock(queueMutex_);
        packetQueue_.emplace(globalPkt, getCurrentTime());
    }

    void processDelayedPackets(JNIEnv* env) {
        if (!env) return;

        cacheProcessPacketMethod(env);
        if (!methodCached_) return;

        std::vector<QueuedPacket> ready;
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            if (packetQueue_.empty()) return;

            auto now = getCurrentTime();
            while (!packetQueue_.empty()) {
                auto& front = packetQueue_.front();
                if ((now - front.timestamp) < delayMs_) break;
                ready.push_back(front);
                packetQueue_.pop();
            }
        }

        if (ready.empty()) return;

        Minecraft mc = Minecraft::getMinecraft(env);
        if (mc.isNull()) {
            for (auto& pkt : ready) {
                if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
            }
            return;
        }

        NetHandlerPlayClient netHandler = mc.getNetHandler();
        if (netHandler.isNull()) {
            for (auto& pkt : ready) {
                if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
            }
            return;
        }

        for (auto& pkt : ready) {
            if (pkt.packet && !env->IsSameObject(pkt.packet, nullptr)) {
                env->CallVoidMethod(pkt.packet, processPacketMethod_, netHandler.getObj());
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                }
            }
            if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
        }
    }

    void processAndClearQueue(JNIEnv* env) {
        if (!env) return;

        cacheProcessPacketMethod(env);

        std::vector<QueuedPacket> all;
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            if (packetQueue_.empty()) return;
            while (!packetQueue_.empty()) {
                all.push_back(packetQueue_.front());
                packetQueue_.pop();
            }
        }

        if (!methodCached_) {
            for (auto& pkt : all) {
                if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
            }
            return;
        }

        Minecraft mc = Minecraft::getMinecraft(env);
        if (mc.isNull()) {
            for (auto& pkt : all) {
                if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
            }
            return;
        }

        NetHandlerPlayClient netHandler = mc.getNetHandler();
        if (netHandler.isNull()) {
            for (auto& pkt : all) {
                if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
            }
            return;
        }

        for (auto& pkt : all) {
            if (pkt.packet && !env->IsSameObject(pkt.packet, nullptr)) {
                env->CallVoidMethod(pkt.packet, processPacketMethod_, netHandler.getObj());
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                }
            }
            if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
        }
    }

    void clearQueue(JNIEnv* env) {
        std::lock_guard<std::mutex> lock(queueMutex_);
        clearQueueInternal(env);
    }

    [[nodiscard]] bool hasPackets() const {
        std::lock_guard<std::mutex> lock(queueMutex_);
        return !packetQueue_.empty();
    }

    [[nodiscard]] size_t getQueueSize() const {
        std::lock_guard<std::mutex> lock(queueMutex_);
        return packetQueue_.size();
    }

    void setDelay(int delayMs) { delayMs_ = delayMs; }
    [[nodiscard]] int getDelay() const { return delayMs_; }


    void queueOutboundPacket(JNIEnv* env, jobject packet) {
        if (!env || !packet) return;

        jobject globalPkt = env->NewGlobalRef(packet);
        if (!globalPkt) return;

        std::lock_guard lock(outboundMutex_);
        outboundQueue_.emplace(globalPkt, getCurrentTime());
    }

    void processOutboundPackets(JNIEnv* env) {
        if (!env) return;

        std::vector<QueuedPacket> ready;
        {
            std::lock_guard<std::mutex> lock(outboundMutex_);
            if (outboundQueue_.empty()) return;

            auto now = getCurrentTime();
            while (!outboundQueue_.empty()) {
                auto& front = outboundQueue_.front();
                if ((now - front.timestamp) < outboundDelayMs_) break;
                ready.push_back(front);
                outboundQueue_.pop();
            }
        }

        if (ready.empty()) return;

        Minecraft mc = Minecraft::getMinecraft(env);
        if (mc.isNull()) {
            for (auto& pkt : ready) {
                if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
            }
            return;
        }

        NetHandlerPlayClient netHandler = mc.getNetHandler();
        if (netHandler.isNull()) {
            for (auto& pkt : ready) {
                if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
            }
            return;
        }

        NetworkManager netManager = netHandler.getNetworkManager();
        if (netManager.isNull()) {
            for (auto& pkt : ready) {
                if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
            }
            return;
        }

        for (auto& pkt : ready) {
            if (pkt.packet && !env->IsSameObject(pkt.packet, nullptr)) {
                netManager.dispatchPacket(pkt.packet);
            }
            if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
        }
    }

    void processAndClearOutboundQueue(JNIEnv* env) {
        if (!env) return;

        std::vector<QueuedPacket> all;
        {
            std::lock_guard<std::mutex> lock(outboundMutex_);
            if (outboundQueue_.empty()) return;
            while (!outboundQueue_.empty()) {
                all.push_back(outboundQueue_.front());
                outboundQueue_.pop();
            }
        }

        Minecraft mc = Minecraft::getMinecraft(env);
        if (mc.isNull()) {
            for (auto& pkt : all) {
                if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
            }
            return;
        }

        NetHandlerPlayClient netHandler = mc.getNetHandler();
        if (netHandler.isNull()) {
            for (auto& pkt : all) {
                if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
            }
            return;
        }

        NetworkManager netManager = netHandler.getNetworkManager();
        if (netManager.isNull()) {
            for (auto& pkt : all) {
                if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
            }
            return;
        }

        for (auto& pkt : all) {
            if (pkt.packet && !env->IsSameObject(pkt.packet, nullptr)) {
                netManager.dispatchPacket(pkt.packet);
            }
            if (pkt.packet) env->DeleteGlobalRef(pkt.packet);
        }
    }

    void clearOutboundQueue(JNIEnv* env) {
        std::lock_guard<std::mutex> lock(outboundMutex_);
        clearOutboundQueueInternal(env);
    }

    [[nodiscard]] bool hasOutboundPackets() const {
        std::lock_guard<std::mutex> lock(outboundMutex_);
        return !outboundQueue_.empty();
    }

    [[nodiscard]] size_t getOutboundQueueSize() const {
        std::lock_guard<std::mutex> lock(outboundMutex_);
        return outboundQueue_.size();
    }

    void setOutboundDelay(int delayMs) { outboundDelayMs_ = delayMs; }
    [[nodiscard]] int getOutboundDelay() const { return outboundDelayMs_; }

    [[nodiscard]] long long getCurrentTime() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

private:
    void cacheProcessPacketMethod(JNIEnv* env) {
        if (methodCached_ || !env) return;

        auto& handler = Mappings::getInstance();
        processPacketMethod_ = handler.getMethod("Packet#processPacket");

        methodCached_ = processPacketMethod_ != nullptr;
    }

    void clearQueueInternal(JNIEnv* env) {
        while (!packetQueue_.empty()) {
            auto& front = packetQueue_.front();
            if (env && front.packet) {
                env->DeleteGlobalRef(front.packet);
            }
            packetQueue_.pop();
        }
    }

    void clearOutboundQueueInternal(JNIEnv* env) {
        while (!outboundQueue_.empty()) {
            auto& front = outboundQueue_.front();
            if (env && front.packet) {
                env->DeleteGlobalRef(front.packet);
            }
            outboundQueue_.pop();
        }
    }
};
