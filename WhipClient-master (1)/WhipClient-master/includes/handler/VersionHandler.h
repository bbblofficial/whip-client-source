#pragma once
#include <vector>
#include <jni.h>

#include "../util/MinecraftDetails.h"

class Version {
public:
	int versionKey;

	const char* minecraftClass;
	const char* theMinecraftField;
	const char* launchedVersionField;
	const char* launchedVersionValue;

	MinecraftVersion minecraftVersion;
	MinecraftLauncher minecraftLauncher;
	ClassResolvingMethod classResolvingMethod;

	const char* specificClassLoaderClass;
	const char* specificClassLoaderField;
	const char* specificClassLoaderSig;

	const char* cmdlineRequired;
};

class VersionHandler {
	std::vector<Version> versions;

public:
	VersionHandler();
	~VersionHandler() = default;
	VersionHandler(const VersionHandler&) = delete;
	VersionHandler& operator=(const VersionHandler&) = delete;

	void registerVersion(Version version);
	bool findVersion(JNIEnv* env, Version* foundVersion);
	bool parseAndRegisterVersions(const char* versionsData, size_t dataSize);
	void clearVersions();

	static VersionHandler& getInstance();
};
