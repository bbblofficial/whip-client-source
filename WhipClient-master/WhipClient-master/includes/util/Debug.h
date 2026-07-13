#pragma once

#include <Windows.h>
#include <cstdio>

#if defined(DEBUGMODE)
void debug_Print(const char* format, ...);
#else
inline void debug_Print(const char* format, ...) {}
#endif


#ifdef WHIP_DEV_MODE
void debug_CreateConsole();
void debug_CloseConsole();
void debug_Log(const char* format, ...);
#define DEBUG_LOG(...) debug_Log(__VA_ARGS__)
#else
inline void debug_CreateConsole() {}
inline void debug_CloseConsole() {}
inline void debug_Log(const char* format, ...) {}
#define DEBUG_LOG(...) do { } while (0)
#endif


#ifdef FASTCAST_VERBOSE_DEBUG
#define fastcast_verbose_print(...) debug_Print(__VA_ARGS__)
#else
#define fastcast_verbose_print(...) do { } while (0)
#endif

#ifdef FASTCAST_VERBOSE_DEBUG
#define fastcast_error_print(...) debug_Print(__VA_ARGS__)
#else
#define fastcast_error_print(...) do { } while (0)
#endif
