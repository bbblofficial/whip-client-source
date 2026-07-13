#pragma once
#include "../../../../../includes/wrapper/primitive/JavaObject.h"

class KeyBinding : public JavaObject {
	static jfieldID pressedId;
	static jfieldID pressTimeId;
	static jfieldID keyCodeId;

	static jclass  lwjglKeyboardClass_;
	static jmethodID isKeyDownMethodId_;

public:
	KeyBinding(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

	bool pressed() {
		if (!pressedId) pressedId = mappings->getField("KeyBinding#pressed");

		return this->env->GetBooleanField(this->obj, pressedId);
	}

	void pressed(bool v) {
		if (!pressedId) pressedId = mappings->getField("KeyBinding#pressed");

		this->env->SetBooleanField(this->obj, pressedId, v);
	}

	int getPressTime() {
		if (!pressTimeId) pressTimeId = mappings->getField("KeyBinding#pressTime");

		return this->env->GetIntField(this->obj, pressTimeId);
	}

	void setPressTime(int v) {
		if (!pressTimeId) pressTimeId = mappings->getField("KeyBinding#pressTime");

		this->env->SetIntField(this->obj, pressTimeId, v);
	}

	int keyCode() {
		if (!keyCodeId) keyCodeId = mappings->getField("KeyBinding#keyCode");

		return this->env->GetIntField(this->obj, keyCodeId);
	}

	void keyCode(int v) {
		if (!keyCodeId) keyCodeId = mappings->getField("KeyBinding#keyCode");

		this->env->SetIntField(this->obj, keyCodeId, v);
	}

	void onTick(int v) {
		if (!keyCodeId) keyCodeId = mappings->getField("KeyBinding#keyCode");

		this->env->SetIntField(this->obj, keyCodeId, v);
	}

	bool isPhysDown() {
		int kc = keyCode();
		if (kc <= 0) return false;

		if (!lwjglKeyboardClass_) {

			jclass threadClass = this->env->FindClass("java/lang/Thread");
			if (!threadClass) { this->env->ExceptionClear(); return false; }
			jmethodID currentThread = this->env->GetStaticMethodID(threadClass, "currentThread", "()Ljava/lang/Thread;");
			if (!currentThread) { this->env->ExceptionClear(); this->env->DeleteLocalRef(threadClass); return false; }
			jobject thread = this->env->CallStaticObjectMethod(threadClass, currentThread);
			if (!thread) { this->env->ExceptionClear(); this->env->DeleteLocalRef(threadClass); return false; }
			jmethodID getCtxCl = this->env->GetMethodID(threadClass, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
			this->env->DeleteLocalRef(threadClass);
			if (!getCtxCl) { this->env->ExceptionClear(); this->env->DeleteLocalRef(thread); return false; }
			jobject classLoader = this->env->CallObjectMethod(thread, getCtxCl);
			this->env->DeleteLocalRef(thread);
			if (!classLoader) { this->env->ExceptionClear(); return false; }

			jclass clClass = this->env->FindClass("java/lang/ClassLoader");
			if (!clClass) { this->env->ExceptionClear(); this->env->DeleteLocalRef(classLoader); return false; }
			jmethodID loadClass = this->env->GetMethodID(clClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
			this->env->DeleteLocalRef(clClass);
			if (!loadClass) { this->env->ExceptionClear(); this->env->DeleteLocalRef(classLoader); return false; }

			jstring className = this->env->NewStringUTF("org.lwjgl.input.Keyboard");
			jobject cls = this->env->CallObjectMethod(classLoader, loadClass, className);
			this->env->DeleteLocalRef(className);
			this->env->DeleteLocalRef(classLoader);
			if (!cls || this->env->ExceptionCheck()) { this->env->ExceptionClear(); return false; }

			lwjglKeyboardClass_ = static_cast<jclass>(this->env->NewGlobalRef(cls));
			this->env->DeleteLocalRef(cls);
		}
		if (!isKeyDownMethodId_) {
			isKeyDownMethodId_ = this->env->GetStaticMethodID(lwjglKeyboardClass_, "isKeyDown", "(I)Z");
			if (!isKeyDownMethodId_) { this->env->ExceptionClear(); return false; }
		}

		jboolean result = this->env->CallStaticBooleanMethod(lwjglKeyboardClass_, isKeyDownMethodId_, kc);
		if (this->env->ExceptionCheck()) { this->env->ExceptionClear(); return false; }
		return result;
	}
};
