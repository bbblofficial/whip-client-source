#pragma once
#include "../../../../../../includes/wrapper/primitive/javaobject.h"
#include "../../../../../../includes/util/mathutils.h"
#include "../../packet.h"

class C07PacketPlayerDigging : public JavaObject {
private:
	static jfieldID statusId;
	static jfieldID positionId;
	static jfieldID facingId;
	static jmethodID constructorId;
	static jfieldID startDestroyBlockId;
	static jfieldID abortDestroyBlockId;
	static jfieldID stopDestroyBlockId;
	static jfieldID dropAllItemsId;
	static jfieldID dropItemId;
	static jfieldID releaseUseItemId;

public:
	C07PacketPlayerDigging(JNIEnv* env, jobject obj) : JavaObject(env, obj) {
		if (!env || !obj) {
			return;
		}
		jclass expectedClass = mappings->getClass("C07PacketPlayerDigging");
		if (!expectedClass) {
			return;
		}
		if (!env->IsInstanceOf(obj, expectedClass)) {
			return;
		}
		makeGlobalRef();
		this->UpdateInstanceObject(this->obj);
	}

	~C07PacketPlayerDigging() {
		if (this->getEnv() && this->GetInstanceObject()) {
			unmakeGlobalRef();
			this->UpdateInstanceObject(nullptr);
		}
	}

	jobject getStatus() {
		if (!statusId) statusId = mappings->getField("C07PacketPlayerDigging#status");
		return this->env->GetObjectField(this->obj, statusId);
	}

	jobject getPosition() {
		if (!positionId) positionId = mappings->getField("C07PacketPlayerDigging#position");
		return this->env->GetObjectField(this->obj, positionId);
	}

	jobject getFacing() {
		if (!facingId) facingId = mappings->getField("C07PacketPlayerDigging#facing");
		return this->env->GetObjectField(this->obj, facingId);
	}

	Vector3<double> GetBlockPosition() const {
		Vector3 pos(0, 0, 0);
		if (!positionId) {
			positionId = mappings->getField("C07PacketPlayerDigging#position");
		}
		if (positionId) {
			jobject blockPos = env->GetObjectField(obj, positionId);
			if (blockPos) {
				jmethodID getXId = mappings->getMethod("Vec3i#getX");
				jmethodID getYId = mappings->getMethod("Vec3i#getY");
				jmethodID getZId = mappings->getMethod("Vec3i#getZ");

				if (getXId && getYId && getZId) {
					pos.X = static_cast<double>(env->CallIntMethod(blockPos, getXId));
					pos.Y = static_cast<double>(env->CallIntMethod(blockPos, getYId));
					pos.Z = static_cast<double>(env->CallIntMethod(blockPos, getZId));
				}
			}
		}
		return pos;
	}

	static Packet sendPacket(JNIEnv* env, jobject action, jobject blockPos, jobject facing) {
		if (!env || !action || !blockPos || !facing) {
			return Packet{ env, NULL };
		}

		jclass packetClass = mappings->getClass("C07PacketPlayerDigging");
		if (!packetClass) {
			return  Packet{ env, NULL };
		}

		if (!constructorId) constructorId = mappings->getMethod("C07PacketPlayerDigging#<init>");
		if (!constructorId) {
			return  Packet{ env, NULL };
		}

		jobject newObj = env->NewObject(packetClass, constructorId, action, blockPos, facing);

		return Packet{ env, newObj };
	}

	static jobject getStartDestroyBlockAction(JNIEnv* env) {
		jclass actionClass = mappings->getClass("C07PacketPlayerDigging$Action");
		if (!actionClass) return nullptr;
		if (!startDestroyBlockId) startDestroyBlockId = mappings->getField("C07PacketPlayerDigging$Action#START_DESTROY_BLOCK");
		if (!startDestroyBlockId) return nullptr;
		return env->GetStaticObjectField(actionClass, startDestroyBlockId);
	}

	static jobject getAbortDestroyBlockAction(JNIEnv* env) {
		jclass actionClass = mappings->getClass("C07PacketPlayerDigging$Action");
		if (!actionClass) return nullptr;
		if (!abortDestroyBlockId) abortDestroyBlockId = mappings->getField("C07PacketPlayerDigging$Action#ABORT_DESTROY_BLOCK");
		if (!abortDestroyBlockId) return nullptr;
		return env->GetStaticObjectField(actionClass, abortDestroyBlockId);
	}

	static jobject getStopDestroyBlockAction(JNIEnv* env) {
		jclass actionClass = mappings->getClass("C07PacketPlayerDigging$Action");
		if (!actionClass) return nullptr;
		if (!stopDestroyBlockId) stopDestroyBlockId = mappings->getField("C07PacketPlayerDigging$Action#STOP_DESTROY_BLOCK");
		if (!stopDestroyBlockId) return nullptr;
		return env->GetStaticObjectField(actionClass, stopDestroyBlockId);
	}

	static jobject getDropAllItemsAction(JNIEnv* env) {
		jclass actionClass = mappings->getClass("C07PacketPlayerDigging$Action");
		if (!actionClass) return nullptr;
		if (!dropAllItemsId) dropAllItemsId = mappings->getField("C07PacketPlayerDigging$Action#DROP_ALL_ITEMS");
		if (!dropAllItemsId) return nullptr;
		return env->GetStaticObjectField(actionClass, dropAllItemsId);
	}

	static jobject getDropItemAction(JNIEnv* env) {
		jclass actionClass = mappings->getClass("C07PacketPlayerDigging$Action");
		if (!actionClass) return nullptr;
		if (!dropItemId) dropItemId = mappings->getField("C07PacketPlayerDigging$Action#DROP_ITEM");
		if (!dropItemId) return nullptr;
		return env->GetStaticObjectField(actionClass, dropItemId);
	}

	static jobject getReleaseUseItemAction(JNIEnv* env) {
		jclass actionClass = mappings->getClass("C07PacketPlayerDigging$Action");
		if (!actionClass) return nullptr;
		if (!releaseUseItemId) releaseUseItemId = mappings->getField("C07PacketPlayerDigging$Action#RELEASE_USE_ITEM");
		if (!releaseUseItemId) return nullptr;
		return env->GetStaticObjectField(actionClass, releaseUseItemId);
	}

	bool isReleaseUseItem() {
		if (!this->env || !this->obj) {
			return false;
		}

		jobject currentStatus = getStatus();
		if (!currentStatus) {
			return false;
		}

		jobject releaseUseItemAction = getReleaseUseItemAction(this->env);
		if (!releaseUseItemAction) {
			this->env->DeleteLocalRef(currentStatus);
			return false;
		}

		jclass objectClass = this->env->FindClass("java/lang/Object");
		jmethodID equalsMethod = this->env->GetMethodID(objectClass, "equals", "(Ljava/lang/Object;)Z");

		bool result = false;
		if (equalsMethod) {
			result = this->env->CallBooleanMethod(currentStatus, equalsMethod, releaseUseItemAction);
		}

		this->env->DeleteLocalRef(currentStatus);
		this->env->DeleteLocalRef(releaseUseItemAction);
		this->env->DeleteLocalRef(objectClass);

		return result;
	}
};
