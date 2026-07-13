#pragma once
#include "../headers/flags.h"
#include "memory"

class c_variables
{
public:

	struct
	{
		float dpi = 1.f;
		int stored_dpi = 150;
		bool dpi_changed = true;

		int tab = 0;
		int stored = 0;
		float alpha = 1.f;

	} gui;

	gui_style style;

};

inline std::unique_ptr<c_variables> var = std::make_unique<c_variables>();
