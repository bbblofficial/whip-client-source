#pragma once
#include <Windows.h>

template<typename T>
class SharedVar {
private:
	bool locked;
	T value;

	void verifyAvailable() {
		while (this->locked) Sleep(1);
	}

public:
	SharedVar(T defaultValue) {
		this->value = defaultValue;
	}

	bool isLocked() {
		return this->locked;
	}

	void lock() {
		this->verifyAvailable();
		this->locked = true;
	}

	void unlock() {
		this->locked = false;
	}

	T getValue() {
		this->verifyAvailable();
		return this->value;
	}

	void wait() {
		this->verifyAvailable();
	}

	void setValue(T value) {
		this->verifyAvailable();
		this->value = value;
	}
};
