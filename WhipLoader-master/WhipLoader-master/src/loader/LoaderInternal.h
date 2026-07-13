#pragma once

// Internal helpers shared between Loader.cpp and steps/*.cpp.
// Not exported in the public Loader.h to keep the public surface clean.

#include "loader/Loader.h"

#include <Windows.h>
#include <whipsyscall/WhipSysCall.h>

namespace loader_detail {

SyscallResolver& WF_Resolver();
void WF_Sleep(DWORD ms);
void WF_GetComputerName(char* dst, u32 dstSize);
void WF_GetOsVersion(char* dst, u32 dstSize);
void WF_GetExecutablePath(char* dst, u32 dstSize);

} // namespace loader_detail
