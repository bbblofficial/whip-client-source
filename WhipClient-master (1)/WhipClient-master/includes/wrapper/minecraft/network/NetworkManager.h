#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"

class NetworkManager : public JavaObject {
private:
    static jmethodID sendPacketId;
    static jmethodID isChannelOpenId;
    static jmethodID closeChannelId;
    static jmethodID processReceivedPacketsId;
    static jmethodID channelRead0Id;
    static jmethodID dispatchPacketId;
    static jfieldID netHandlerId;
    static jfieldID packetListenerId;

public:
    NetworkManager(JNIEnv* env, jobject obj) : JavaObject(env, obj) {
        if (!env || !obj) {
            return;
        }

        jclass expectedClass = mappings->getClass("NetworkManager");
        if (!expectedClass) {
            return;
        }

        if (!env->IsInstanceOf(obj, expectedClass)) {
            return;
        }

        makeGlobalRef();
        this->UpdateInstanceObject(this->obj);
    }

    ~NetworkManager() {
        if (this->getEnv() && this->GetInstanceObject()) {
            unmakeGlobalRef();
            this->UpdateInstanceObject(nullptr);
        }
    }

    void sendPacket(jobject packet) {
        if (!sendPacketId) sendPacketId = mappings->getMethod("NetworkManager#sendPacket");

        this->env->CallVoidMethod(this->obj, sendPacketId, packet);
    }

    bool isChannelOpen() {
        if (!isChannelOpenId) isChannelOpenId = mappings->getMethod("NetworkManager#isChannelOpen");

        return this->env->CallBooleanMethod(this->obj, isChannelOpenId);
    }

    void closeChannel(jobject reason) {
        if (!closeChannelId) closeChannelId = mappings->getMethod("NetworkManager#closeChannel");

        this->env->CallVoidMethod(this->obj, closeChannelId, reason);
    }

    void processReceivedPackets() {
        if (!processReceivedPacketsId) processReceivedPacketsId = mappings->getMethod("NetworkManager#processReceivedPackets");

        this->env->CallVoidMethod(this->obj, processReceivedPacketsId);
    }

    void channelRead0(jobject ctx, jobject packet) {
        if (!channelRead0Id) channelRead0Id = mappings->getMethod("NetworkManager#channelRead0");

        this->env->CallVoidMethod(this->obj, channelRead0Id, ctx, packet);
    }

    jobject getNetHandler() {
        if (!netHandlerId) netHandlerId = mappings->getField("NetworkManager#packetListener");

        return this->env->GetObjectField(this->obj, netHandlerId);
    }

    jobject getPacketListener() {
        if (!packetListenerId) packetListenerId = mappings->getField("NetworkManager#packetListener");

        return this->env->GetObjectField(this->obj, packetListenerId);
    }

    void dispatchPacket(jobject packet) {
        if (!dispatchPacketId) dispatchPacketId = mappings->getMethod("NetworkManager#dispatchPacket");

        static jobjectArray emptyListeners = nullptr;
        if (!emptyListeners) {
            jclass listenerClass = this->env->FindClass("io/netty/util/concurrent/GenericFutureListener");
            if (listenerClass) {
                jobjectArray local = this->env->NewObjectArray(0, listenerClass, nullptr);
                if (local) {
                    emptyListeners = (jobjectArray) this->env->NewGlobalRef(local);
                    this->env->DeleteLocalRef(local);
                }
                this->env->DeleteLocalRef(listenerClass);
            }
            if (this->env->ExceptionCheck()) this->env->ExceptionClear();
        }

        this->env->CallVoidMethod(this->obj, dispatchPacketId, packet, emptyListeners);

        if (this->env->ExceptionCheck()) {
            this->env->ExceptionClear();
        }
    }
};
