#pragma once

#include "jni.h"
#include "../../handler/MappingHandler.h"

class JavaObject {
protected:
	JNIEnv* env;
	jobject obj;
	bool isGlobalRef = false;
	bool deleteRef = true;
	jobject InstanceObject = nullptr;

	static Mappings* mappings;

public:
	JavaObject(JNIEnv* env, jobject obj) {
		this->env = env;
		this->obj = obj;
	}

	~JavaObject() {
		if (env && obj && deleteRef) {
			if (isGlobalRef) {
				env->DeleteGlobalRef(obj);
			} else {
				env->DeleteLocalRef(obj);
			}
		}
	}

	void setDeleteRef(const bool value) {
		this->deleteRef = value;
	}

	bool isNull() const {
		return !this->env || !this->obj;
	}

	bool isEqual(JavaObject javaObject) {
		return this->env->IsSameObject(this->obj, javaObject.getObj());
	}

	void reset() {
		this->env = nullptr;
		this->obj = nullptr;
	}

	bool isInstanceOf(std::string clazzName) {
		if (this->isNull()) return false;
		jclass clazz = this->mappings->getClass(clazzName);
		if (!clazz) return false;

		if (this->env->ExceptionCheck()) {
			this->env->ExceptionClear();
		}

		bool result = this->env->IsInstanceOf(this->obj, clazz);

		if (this->env->ExceptionCheck()) {
			this->env->ExceptionClear();
			return false;
		}

		return result;
	}

	bool isInstanceOf(jclass clazz) {
		if (this->isNull()) return false;
		if (!clazz) return false;

		if (this->env->ExceptionCheck()) {
			this->env->ExceptionClear();
		}

		bool result = this->env->IsInstanceOf(this->obj, clazz);

		if (this->env->ExceptionCheck()) {
			this->env->ExceptionClear();
			return false;
		}

		return result;
	}

	template<typename T = JavaObject>
	T convertTo() {
		return *(T*) this;
	}

	template<typename T = JavaObject>
	T& safeConvertTo() & {
		static_assert(std::is_base_of_v<JavaObject, T>, "T must inherit from JavaObject");
		return reinterpret_cast<T&>(*this);
	}

	template<typename T = JavaObject>
	T UHQConvertTo() {
		deleteRef = false;
		return T { this->env, this->obj };
	}

	template<typename T = JavaObject>
	T invertUHQConvertTo() {
		T value{ this->env, this->obj };
		value.setDeleteRef(false);
		return value;
	}

	template<typename T = JavaObject>
	const T& safeConvertTo() const & {
		static_assert(std::is_base_of_v<JavaObject, T>, "T must inherit from JavaObject");
		return reinterpret_cast<const T&>(*this);
	}

	template<typename T = JavaObject>
	T&& safeConvertTo() && = delete;

	template<typename T = JavaObject>
	T fromObj(jobject obj) {
		JavaObject javaObject = { this->env, obj };
		return *((T*)&javaObject);
	}

	void setEnv(JNIEnv* env) { this->env = env; }
	JNIEnv* getEnv() { return this->env; }

	void setObj(jobject obj) { this->obj = obj; }
	jobject getObj() { return this->obj; }
	jobject getObj() const { return this->obj; }

	static void setMappings(Mappings* m) { mappings = m; }
	static Mappings* getMappings() { return mappings; }

	void makeGlobalRef() {
		auto tempObj = this->env->NewGlobalRef(this->obj);
		this->isGlobalRef = true;
		this->obj = tempObj;
	}

	void unmakeGlobalRef() {
		this->env->DeleteGlobalRef(this->obj);
		this->isGlobalRef = false;
		this->obj;
	}

	void UpdateInstanceObject(jobject obj) {
		this->InstanceObject = obj;
	}

	jobject GetInstanceObject() {
		return this->InstanceObject;
	}
};

static JavaObject NULL_JAVAOBJECT = { NULL, NULL };
