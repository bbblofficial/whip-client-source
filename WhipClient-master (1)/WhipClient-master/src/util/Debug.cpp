#include "../../includes/util/Debug.h"
#include <cstdarg>
#include <cstdio>
#include <io.h>
#include <fcntl.h>

#ifdef DEBUGMODE
void debug_Print(const char* format, ...) {
    char buffer[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    SYSTEMTIME st;
    GetLocalTime(&st);

    char line[2200];
    snprintf(line, sizeof(line), "[%02d:%02d:%02d.%03d] %s\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buffer);

    OutputDebugStringA(line);
}
#endif

#ifdef WHIP_DEV_MODE
static FILE* console_stdout = nullptr;
static FILE* console_stderr = nullptr;

void debug_CreateConsole() {

    if (!AllocConsole()) {
        return;
    }


    SetConsoleTitleA("Whip Client - Debug Console (DEV MODE)");


    freopen_s(&console_stdout, "CONOUT$", "w", stdout);
    freopen_s(&console_stderr, "CONOUT$", "w", stderr);


    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);


    printf("===========================================\n");
    printf("  Whip Client - Debug Console\n");
    printf("  Mode: DEVELOPMENT\n");
    printf("  Build: %s %s\n", __DATE__, __TIME__);
    printf("===========================================\n\n");
}

void debug_CloseConsole() {
    if (console_stdout) {
        fclose(console_stdout);
        console_stdout = nullptr;
    }
    if (console_stderr) {
        fclose(console_stderr);
        console_stderr = nullptr;
    }
    FreeConsole();
}

void debug_Log(const char* format, ...) {
    char buffer[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);


    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[%02d:%02d:%02d.%03d] %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buffer);
}
#endif
