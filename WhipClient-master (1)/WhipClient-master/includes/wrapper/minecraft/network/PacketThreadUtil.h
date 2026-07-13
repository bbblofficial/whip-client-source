#pragma once
#include "../../../../includes/wrapper/primitive/javaobject.h"

class PacketThreadUtil : public JavaObject {
private:
	static jmethodID checkThreadAndEnqueueId;

public:
	PacketThreadUtil(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

	static void checkThreadAndEnqueue(JNIEnv* env, jclass clazz, jobject packet, jobject netHandler, jobject threadListener) {
		if (!checkThreadAndEnqueueId) checkThreadAndEnqueueId = mappings->getMethod("PacketThreadUtil#checkThreadAndEnqueue");
		env->CallStaticVoidMethod(clazz, checkThreadAndEnqueueId, packet, netHandler, threadListener);
	}
};
