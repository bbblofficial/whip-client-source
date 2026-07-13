#pragma once
#include "MinHook.h"

class Hook {
private:
	void* target;
	void* detour;
	void* original;

public:
	Hook(void* target, void* detour) {
		this->target = target;
		this->detour = detour;
	}

	bool create() {
		return MH_CreateHook(this->target, this->detour, &this->original) == MH_OK;
	}

	bool remove() {
		return MH_RemoveHook(this->target) == MH_OK;
	}

	void enable() {
		MH_EnableHook(this->target);
	}

	void disable() {
		MH_DisableHook(this->target);
	}

	template <typename T>
	T getOriginal() {
		return reinterpret_cast<T>(this->original);
	}
};
