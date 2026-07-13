#pragma once

#include <Windows.h>
#include <jni.h>
#include <map>
#include <memory>

#include "imgui.h"
#include "screen/IScreen.h"

class Hook;

class Gui {
    std::map<ScreenType, std::unique_ptr<IScreen>> screens;

    ImVec2 Size;

    ScreenType screenType = NONE;

    using swapBuffersSig = bool (*)(HDC);

    bool shouldStop = false;
    bool isRunning = false;

    HWND targetWindow = nullptr;
    LONG_PTR lastWindowProc = NULL;
    Hook* swapBuffersHook = nullptr;
    HANDLE loopThreadHandle = nullptr;
    void* originalSwapBuffersAddr = nullptr;

    HDC openglDC = nullptr;
    HGLRC openglRC = nullptr;

    bool open = false;
    POINT cursorPos = {};

    int hideBind1 = 0;

    int nextHideBind = 0;
    int hideBindCount = 0;

    int randomMsgCount = 0;

    bool requestUnload = false;

    bool hudEnabled = true;

    JNIEnv* jvmEnv = nullptr;
    JavaVM* jvm = nullptr;

    static LRESULT WINAPI windowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static bool swapBuffersProc(HDC hdc);
    void drawing(RECT rect) const;
    static DWORD WINAPI loop(LPVOID param);

public:
    Gui() = default;
    ~Gui() = default;

    Gui(const Gui&) = delete;
    Gui& operator=(const Gui&) = delete;

    int destructBind = VK_F7;
    int panicBind = 0;

    bool init();
    bool start() const;
    bool stop();
    bool clear();

    bool safeUnload();

    void setScreen(const ScreenType screenType) {
        this->screenType = screenType;
    }

    bool hasRequestUnload() const {
        return this->requestUnload;
    }

    bool isOpen() const {
        return this->open;
    }

    void addScreen(std::unique_ptr<IScreen> screen) {
        screens[screen->getType()] = std::move(screen);
    }

    IScreen* getScreen(const ScreenType type) const {
        if (const auto it = screens.find(type); it != screens.end()) {
            return it->second.get();
        }
        return nullptr;
    }

    void setJVM(JavaVM* javaVM) { jvm = javaVM; }

    bool enableGui = false;
    int hideBind0 = 0;

    static Gui& getInstance();
};
