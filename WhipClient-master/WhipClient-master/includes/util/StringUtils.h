#pragma once
#include <string.h>

static wchar_t getTextFirstColorCode(wchar_t* buff) {
	const wchar_t* colors = L"0123456789abcdef";

	size_t len = wcslen(buff), i, a;
	for (i = 0; i < len; i++) {
		if (buff[i] != L'§' || i + 1 == len) continue;
		for (a = 0; a < 16; a++) {
			if (buff[i + 1] == colors[a]) return colors[a];
		}
	}
	return 0;
}
