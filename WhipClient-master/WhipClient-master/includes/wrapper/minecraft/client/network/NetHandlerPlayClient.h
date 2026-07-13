#pragma once

#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../network/Packet.h"
#include "../../network/NetworkManager.h"
#include "../../client/multiplayer/worldclient.h"
#include "../gui/GuiPlayerInfo.h"
#include "../../../../../includes/util/Debug.h"

class NetHandlerPlayClient : public JavaObject {
private:
	static jmethodID addToSendQueueId;
	static jfieldID gameControllerId;
	static jfieldID clientWorldControllerId;
	static jfieldID netManagerId;
	static jfieldID playerInfoListId;
public:
	NetHandlerPlayClient(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

	void addToSendQueue(Packet packet) {
		if (!addToSendQueueId) addToSendQueueId = mappings->getMethod("NetHandlerPlayClient#addToSendQueue");

		this->env->CallVoidMethod(this->obj, addToSendQueueId, packet.getObj());
	}

	jobject getGameController() {
		if (!gameControllerId) gameControllerId = mappings->getField("NetHandlerPlayClient#gameController");
		return this->env->GetObjectField(this->obj, gameControllerId);
	}

	WorldClient getClientWorldController() {
		if (!clientWorldControllerId) clientWorldControllerId = mappings->getField("NetHandlerPlayClient#clientWorldController");

		jobject obj = this->env->GetObjectField(this->obj, clientWorldControllerId);
		if (!obj) return { NULL, NULL };

		return { this->env, obj };
	}

	NetworkManager getNetworkManager() const {
		if (!netManagerId) netManagerId = mappings->getField("NetHandlerPlayClient#netManager");

		const jobject netManager = this->env->GetObjectField(this->obj, netManagerId);
		return NetworkManager{this->env, netManager};
	}

	jobject getPlayerInfoMap() {
		if (!playerInfoListId) {
			playerInfoListId = mappings->getField("NetHandlerPlayClient#playerInfoMap");
		}
		if (!playerInfoListId) {
			return nullptr;
		}

		jobject mapObj = this->env->GetObjectField(this->obj, playerInfoListId);
		return mapObj;
	}

	int getCurrentPlayerPing() {

		jobject mapObj = getPlayerInfoMap();
		if (!mapObj) return 50;

		jclass mapClass = this->env->FindClass("java/util/Map");
		if (!mapClass || this->env->ExceptionCheck()) {
			if (this->env->ExceptionCheck()) this->env->ExceptionClear();
			return 50;
		}

		jmethodID valuesMethod = this->env->GetMethodID(mapClass, "values", "()Ljava/util/Collection;");
		if (!valuesMethod) {
			this->env->DeleteLocalRef(mapClass);
			return 50;
		}

		jobject valuesCollection = this->env->CallObjectMethod(mapObj, valuesMethod);
		this->env->DeleteLocalRef(mapClass);
		if (!valuesCollection || this->env->ExceptionCheck()) {
			if (this->env->ExceptionCheck()) this->env->ExceptionClear();
			return 50;
		}

		jclass collectionClass = this->env->FindClass("java/util/Collection");
		if (!collectionClass || this->env->ExceptionCheck()) {
			if (this->env->ExceptionCheck()) this->env->ExceptionClear();
			this->env->DeleteLocalRef(valuesCollection);
			return 50;
		}
		jmethodID sizeMethod = this->env->GetMethodID(collectionClass, "size", "()I");
		int size = this->env->CallIntMethod(valuesCollection, sizeMethod);
		if (this->env->ExceptionCheck()) { this->env->ExceptionClear(); this->env->DeleteLocalRef(collectionClass); this->env->DeleteLocalRef(valuesCollection); return 50; }

		if (size == 0) {
			this->env->DeleteLocalRef(collectionClass);
			this->env->DeleteLocalRef(valuesCollection);
			return 50;
		}

		jmethodID iteratorMethod = this->env->GetMethodID(collectionClass, "iterator", "()Ljava/util/Iterator;");
		jobject iterator = this->env->CallObjectMethod(valuesCollection, iteratorMethod);
		this->env->DeleteLocalRef(collectionClass);
		this->env->DeleteLocalRef(valuesCollection);
		if (!iterator || this->env->ExceptionCheck()) {
			if (this->env->ExceptionCheck()) this->env->ExceptionClear();
			return 50;
		}

		jclass iteratorClass = this->env->FindClass("java/util/Iterator");
		if (!iteratorClass) { this->env->DeleteLocalRef(iterator); return 50; }
		jmethodID nextMethod = this->env->GetMethodID(iteratorClass, "next", "()Ljava/lang/Object;");
		jobject playerInfoObj = this->env->CallObjectMethod(iterator, nextMethod);
		this->env->DeleteLocalRef(iteratorClass);
		this->env->DeleteLocalRef(iterator);
		if (!playerInfoObj || this->env->ExceptionCheck()) {
			if (this->env->ExceptionCheck()) this->env->ExceptionClear();
			return 50;
		}

		GuiPlayerInfo playerInfo(this->env, playerInfoObj);
		int ping = playerInfo.getResponseTime();
		if (this->env->ExceptionCheck()) { this->env->ExceptionClear(); ping = 50; }
		this->env->DeleteLocalRef(playerInfoObj);

		return ping;
	}

};
