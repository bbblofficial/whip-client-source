#pragma once
#include "../../../../../../includes/wrapper/primitive/javaobject.h"
#include <vector>

class S13PacketDestroyEntities : public JavaObject {
private:
	static jfieldID entityIdsId;

public:
	S13PacketDestroyEntities(JNIEnv* env, jobject obj) : JavaObject(env, obj) {
		if (!env || !obj) {
			return;
		}

		jclass expectedClass = mappings->getClass("S13PacketDestroyEntities");
		if (!expectedClass) {
			return;
		}

		if (!env->IsInstanceOf(obj, expectedClass)) {
			return;
		}

	}

	~S13PacketDestroyEntities() {

	}

	std::vector<int> getEntityIds() {
		std::vector<int> result;

		if (!entityIdsId) entityIdsId = mappings->getField("S13PacketDestroyEntities#entityIDs");
		if (!entityIdsId) return result;

		auto entityIDsArray = static_cast<jintArray>(this->env->GetObjectField(this->obj, entityIdsId));
		if (!entityIDsArray) return result;

		jsize length = this->env->GetArrayLength(entityIDsArray);
		jint* ids = this->env->GetIntArrayElements(entityIDsArray, nullptr);

		if (ids) {
			result.reserve(length);
			for (jsize i = 0; i < length; i++) {
				result.push_back(ids[i]);
			}
			this->env->ReleaseIntArrayElements(entityIDsArray, ids, 0);
		}

		this->env->DeleteLocalRef(entityIDsArray);
		return result;
	}

	bool containsEntityId(int entityId) {
		if (!entityIdsId) entityIdsId = mappings->getField("S13PacketDestroyEntities#entityIDs");
		if (!entityIdsId) return false;

		auto entityIDsArray = static_cast<jintArray>(this->env->GetObjectField(this->obj, entityIdsId));
		if (!entityIDsArray) return false;

		jsize length = this->env->GetArrayLength(entityIDsArray);
		jint* ids = this->env->GetIntArrayElements(entityIDsArray, nullptr);

		bool found = false;
		if (ids) {
			for (jsize i = 0; i < length; i++) {
				if (ids[i] == entityId) {
					found = true;
					break;
				}
			}
			this->env->ReleaseIntArrayElements(entityIDsArray, ids, 0);
		}

		this->env->DeleteLocalRef(entityIDsArray);
		return found;
	}
};
