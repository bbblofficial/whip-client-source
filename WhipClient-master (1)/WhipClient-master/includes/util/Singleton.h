#pragma once

#include <cstring>

template<typename T>
class Instance {
protected:
	Instance() {}
	~Instance() {}

	Instance(const Instance&) = delete;
	Instance& operator=(const Instance&) = delete;

	Instance(Instance&&) = delete;
	Instance& operator=(Instance&&) = delete;

public:
	static auto Get() {
		static T inst{};
		return &inst;
	}

	static void Destroy() {
		T* inst = Get();
		if (inst) {
			inst->~T();
			std::memset(inst, 0, sizeof(T));
		}
	}
};
