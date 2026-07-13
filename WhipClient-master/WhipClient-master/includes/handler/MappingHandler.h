#pragma once

#include <unordered_map>
#include <string>
#include <jni.h>

#include "../util/MinecraftDetails.h"

class Mappings {
	JNIEnv* env;
	ClassResolvingMethod method;

	std::unordered_map<std::string, jclass> classes;
	std::unordered_map<std::string, jfieldID> fields;
	std::unordered_map<std::string, jmethodID> methods;
	std::unordered_map<std::string, jobject> objects;

	mutable jobject cachedClassLoader;

	jclass findClass(const std::string &className) const;

public:
	Mappings();
	~Mappings();

	Mappings(const Mappings&) = delete;
	Mappings& operator=(const Mappings&) = delete;

	jclass getClass(const std::string &key);
	jfieldID getField(const std::string &key);
	jmethodID getMethod(const std::string &key);
	jobject getObject(const std::string &key);

	jobject getGameClassLoader() const { return cachedClassLoader; }

	bool registerMappingsFromWbin(const unsigned char *data, size_t size);

	void clearMappings();

	void setEnv(JNIEnv* env);
	void setMethod(ClassResolvingMethod method);

	static Mappings& getInstance();
};
