#pragma once

enum class ClassResolvingMethod {
	ROOT_CLASSLOADER       = 0,
	THREADS_CLASSLOADER    = 1,
	SPECIFIC_CLASSLOADER   = 2,

	DISCOVERED_CLASSLOADER = 3
};

enum class MinecraftVersion {
	V1_7_10 = 0, V1_8_9 = 1
};

enum class MinecraftLauncher {
	L_LUNAR = 0, L_BADLION = 1, L_CHEATBREAKER = 2, L_FORGE = 3, L_VANILLA = 4, L_MENORIA = 5
};

class MinecraftSession {
public:
	MinecraftSession() = default;
	~MinecraftSession() = default;
	MinecraftSession(const MinecraftSession&) = delete;
	MinecraftSession& operator=(const MinecraftSession&) = delete;

	MinecraftVersion version;
	MinecraftLauncher launcher;

	static MinecraftSession& getInstance();
};
