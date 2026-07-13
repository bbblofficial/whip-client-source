// NOTE: do NOT add `#pragma optimize("", off)` here. It disables ALL
// optimizations for the TU — including __forceinline of ad::spoof_my_ra(),
// which MUST be inlined into WinMain for _AddressOfReturnAddress to resolve
// to WinMain's RA slot. Without inlining, spoof corrupts its OWN frame and
// AVs on return. The flags in CMakeLists already set /Od /Ob2 for Debug,
// which preserves __forceinline.
#include "application/Application.h"
#include <Windows.h>
#include "security/AntiRpmGuard.h"
#include "security/Sentinel.h"
#include "ui/IConsoleUI.h"
#include "util/ConsoleUtils.h"
#include <Windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <exception>

#include "antidebug/stack/stack_cpp.hpp"

extern "C" IMAGE_DOS_HEADER __ImageBase;

static BOOL WINAPI consoleCtrlHandler(DWORD ctrl) {
    if (ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT || ctrl == CTRL_CLOSE_EVENT) {
        app().requestExit(0);
    }
    return TRUE;
}

static LONG WINAPI crashHandler(EXCEPTION_POINTERS* ep) {
    char msg[256];
    sprintf_s(msg, "WhipClient crashed.\nException code: 0x%08X\nAddress: 0x%p",
        ep->ExceptionRecord->ExceptionCode,
        ep->ExceptionRecord->ExceptionAddress);
    MessageBoxA(nullptr, msg, "Fatal Error", MB_OK | MB_ICONERROR);
    return EXCEPTION_EXECUTE_HANDLER;
}

static void waitBeforeExit() {
    fflush(stdout);
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    if (hInput != INVALID_HANDLE_VALUE) {
        FlushConsoleInputBuffer(hInput);
        INPUT_RECORD ir;
        DWORD read;
        while (ReadConsoleInput(hInput, &ir, 1, &read)) {
            if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) break;
        }
    }
}

static void ensureConsole() {
    if (!GetConsoleWindow()) {
        AllocConsole();
    }
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    freopen_s(&fp, "CONIN$", "r", stdin);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;

    // FIRST thing: spoof WinMain's saved-RA. Must run from WinMain itself —
    // __forceinline ensures _AddressOfReturnAddress resolves to WinMain's slot.
    // Safe because we exit via ExitThread(0), never unwinding back through
    // the corrupted slot.
    //
    // SKIPPED in BYPASS mode: WinMain is called from a worker thread spawned
    // by DllMain (after manual-map dispatch), not from the EXE entry. The
    // _AddressOfReturnAddress() points to WhipBypassWorker's frame slot, so
    // spoofing it corrupts the worker thread's RA — fine in theory because
    // we ExitThread, but the corrupted bytes can be read by anti-debug heuristics
    // elsewhere and trigger a flurry of AV/DIV0/ASSERTION exceptions ending
    // in a fatal AV that takes down Lunar.
#ifndef WHIP_BYPASS_MODE
    ad::spoof_my_ra();
#endif

    // Stack protection: noise threads + gadget/decoy pools (shared by
    // ad::StackHidden guards in auth/dll TUs). RAII teardown.
    ad::StackProtect stackProtect{AD_SP_PROFILE_BALANCED};


#ifndef WHIP_UI_IMGUI
    Utils::createConsole();
    Utils::hideCursor();
    Utils::disableResize();
    Utils::disableConsoleSelection();
#endif

    SetUnhandledExceptionFilter(crashHandler);
#ifndef WHIP_UI_IMGUI
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
#endif

    // Sentinel anti-crack — DOIT être init avant tout I/O réseau pour que le
    // score initial soit pris dans un environnement encore "froid". Tout appel
    // ultérieur à Sentinel::taint utilisera ce score (et ses recheck) pour
    // corrompre les requêtes envoyées au serveur si un debugger est détecté.
    // Required even in bypass mode: AuthenticateStep calls Sentinel::recheck
    // and Sentinel::deriveAuthTag — skipping init yields garbage auth_tag,
    // which the server rejects ("Error #10").
    Sentinel::init();

    // Anti-RPM guard — background thread enumerates handles every ~15s; if an
    // external process holds a PROCESS_VM_READ handle on us, it folds a
    // non-zero pattern into the Sentinel score, corrupting auth_tag → server
    // rejects → auto-ban. Whitelists Explorer / system / AV by image name.
#ifndef WHIP_BYPASS_MODE
    AntiRpmGuard::start();
#endif

    Application& application = app();

    auto initResult = application.initialize();
    if (!initResult) {
        auto* ui = application.ui();
        if (ui) {
            ui->showError(initResult.error().message);
            ui->waitForKey();
        } else {
            waitBeforeExit();
        }
        return 1;
    }
    int exitCode = application.run();

#ifndef WHIP_UI_IMGUI
    {
        FILE* fp = nullptr;
        freopen_s(&fp, "NUL", "w", stdout);
        freopen_s(&fp, "NUL", "w", stderr);
        freopen_s(&fp, "NUL", "r", stdin);
        if (HWND h = GetConsoleWindow()) ShowWindow(h, SW_HIDE);
#ifdef WHIP_BYPASS_MODE
        FreeConsole();
#endif
    }
#endif

#ifndef WHIP_BYPASS_MODE
    {
        struct WdCtx { DWORD ms; DWORD code; };
        WdCtx* wdctx = new WdCtx{ 3000, static_cast<DWORD>(exitCode) };
        HANDLE wd = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
            WdCtx* c = static_cast<WdCtx*>(p);
            Sleep(c->ms);
            DWORD code = c->code;
            delete c;
            TerminateProcess(GetCurrentProcess(), code);
            return 0;
        }, wdctx, 0, nullptr);
        if (wd) CloseHandle(wd);
        else { delete wdctx; }
    }
#endif

    application.shutdown();

#ifndef WHIP_BYPASS_MODE
    {
        HANDLE doneEvt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE t = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
            AntiRpmGuard::stop();
            SetEvent(static_cast<HANDLE>(p));
            return 0;
        }, doneEvt, 0, nullptr);
        if (t) {
            WaitForSingleObject(doneEvt, 3000);
            CloseHandle(t);
        }
        if (doneEvt) CloseHandle(doneEvt);
    }
#endif

    {
        HANDLE doneEvt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE t = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
            Sentinel::cleanup();
            SetEvent(static_cast<HANDLE>(p));
            return 0;
        }, doneEvt, 0, nullptr);
        if (t) {
            WaitForSingleObject(doneEvt, 3000);
            CloseHandle(t);
        }
        if (doneEvt) CloseHandle(doneEvt);
    }

#ifdef WHIP_BYPASS_MODE
    ExitThread(static_cast<DWORD>(exitCode));
#else
    TerminateProcess(GetCurrentProcess(), static_cast<UINT>(exitCode));
#endif
    return exitCode;
}

#pragma optimize("", on)

#ifdef WHIP_BYPASS_MODE
// Manual-mapped DLL entry. WhipMmap dispatches DllMain(DLL_PROCESS_ATTACH)
// after applying relocations + imports + TLS callbacks, so by the time we
// get here the image is fully usable. We must NOT block the caller (its
// stack is doing the dispatch), so we spawn a thread and route it into
// WinMain — the existing path handles BYPASS-mode shutdown via ExitThread.
static DWORD WINAPI WhipBypassWorker(LPVOID /*param*/) {
    int rc = WinMain(GetModuleHandleW(nullptr), nullptr, nullptr, SW_HIDE);
    return static_cast<DWORD>(rc);
}

extern "C" BOOL WINAPI DllMain(HINSTANCE /*hInst*/, DWORD reason, LPVOID /*reserved*/) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    HANDLE h = CreateThread(nullptr, 0, &WhipBypassWorker, nullptr, 0, nullptr);
    if (!h) { return TRUE; }
    CloseHandle(h);
    return TRUE;
}
#endif
