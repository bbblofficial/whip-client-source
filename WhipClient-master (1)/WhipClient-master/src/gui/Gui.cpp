#define _WINSOCKAPI_

#include "../../includes/gui/Gui.h"

#define STB_IMAGE_IMPLEMENTATION
#include "ClientMain.h"
#include "Hook.h"
#include "imgui_impl_opengl2.h"
#include "imgui_impl_win32.h"
#include "bus/EventBus.h"
#include "event/sub/Render2dEvent.h"
#include "event/sub/Render3dEvent.h"
#include "includes/module/impl/visual/nametagmodule.h"
#include "includes/module/impl/visual/NotificationModule.h"
#include "includes/module/impl/visual/WatermarkModule.h"

#include "gui/includes.h"
#include "handler/ModuleHandler.h"
#include "module/CategoryType.h"
#include "screen/base/BaseScreen.h"
#include "screen/sub/ModuleScreen.h"
#include "task/impl/InputTask.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include "util/ClientStrings.h"
#include "manager/ConfigManager.h"

LRESULT WINAPI Gui::windowProc(const HWND hWnd, const UINT msg, const WPARAM wParam, const LPARAM lParam) {
    constexpr auto isMouseMessage = [](const UINT message) -> bool {
        return (message >= WM_MOUSEFIRST && message <= WM_MOUSELAST) ||
               message == WM_MOUSEWHEEL || message == WM_MOUSEHWHEEL ||
               message == WM_NCMOUSEMOVE || message == WM_NCLBUTTONDOWN ||
               message == WM_NCLBUTTONUP || message == WM_NCRBUTTONDOWN ||
               message == WM_NCRBUTTONUP || message == WM_NCMBUTTONDOWN ||
               message == WM_NCMBUTTONUP || message == WM_NCXBUTTONDOWN ||
               message == WM_NCXBUTTONUP;
    };

    if (getInstance().open) {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;
    }

    if (shouldBlockKeyDown()) {
        if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN || msg == WM_KEYUP || msg == WM_SYSKEYUP ||
            msg == WM_CHAR || msg == WM_SYSCHAR || msg == WM_DEADCHAR || msg == WM_SYSDEADCHAR) {
            return 1;
        }
        if (isMouseMessage(msg)) {
            return 1;
        }
    }

    if (msg == WM_KEYDOWN) {

        WPARAM resolvedKey = wParam;
        if (wParam == VK_SHIFT || wParam == VK_CONTROL || wParam == VK_MENU) {
            UINT scanCode = (lParam >> 16) & 0xFF;
            bool extended = (lParam >> 24) & 1;
            resolvedKey = MapVirtualKey(scanCode, MAPVK_VSC_TO_VK_EX);
            if (resolvedKey == 0) resolvedKey = wParam;
        }

        if (resolvedKey == getInstance().hideBind0 && (getInstance().hideBind0 == getInstance().hideBind1 || getInstance().hideBind1 == 0)) {
            getInstance().hideBindCount = 2;
        }
        else if (resolvedKey == getInstance().hideBind0 && (getInstance().nextHideBind == 0 || getInstance().nextHideBind == getInstance().hideBind0)) {
            getInstance().nextHideBind = getInstance().hideBind1;
            getInstance().hideBindCount++;
        }
        else if (resolvedKey == getInstance().hideBind1 && (getInstance().nextHideBind == 0 || getInstance().nextHideBind == getInstance().hideBind1)) {
            getInstance().nextHideBind = getInstance().hideBind0;
            getInstance().hideBindCount++;
        }
        else if (resolvedKey == getInstance().destructBind) {
            getInstance().requestUnload = true;
        }
        else if (getInstance().panicBind != 0 && resolvedKey == getInstance().panicBind) {
            ModuleHandler::getInstance().panicAll();
        }
        else {
            getInstance().randomMsgCount++;
        }
    }

    if (getInstance().randomMsgCount >= 10) {
        getInstance().randomMsgCount = 0;
        getInstance().nextHideBind = 0;
        getInstance().hideBindCount = 0;
    }

    if (getInstance().hideBindCount == 2) {
        getInstance().nextHideBind = 0;
        getInstance().hideBindCount = 0;

        getInstance().open = !getInstance().open;

        if (getInstance().open) {
            ShowCursor(true);
            GetCursorPos(&getInstance().cursorPos);
        }
        else {
            ShowCursor(false);
            SetCursorPos(getInstance().cursorPos.x, getInstance().cursorPos.y);
        }
    }

    if (getInstance().open && msg == WM_KEYDOWN && wParam == VK_ESCAPE) {
        getInstance().open = false;
        ShowCursor(false);
        SetCursorPos(getInstance().cursorPos.x, getInstance().cursorPos.y);
        return 1;
    }

    if (getInstance().open && isMouseMessage(msg)) {
        return 1;
    }

    return CallWindowProcA(reinterpret_cast<WNDPROC>(getInstance().lastWindowProc), hWnd, msg, wParam, lParam);
}

bool update;

bool Gui::swapBuffersProc(const HDC hdc) {
    if (!hdc) {
        if (getInstance().swapBuffersHook) {
            return getInstance().swapBuffersHook->getOriginal<swapBuffersSig>()(hdc);
        }
        return false;
    }

    if (getInstance().shouldStop) {
        if (getInstance().jvm && getInstance().jvmEnv) {
            JNIEnv* testEnv = nullptr;
            if (getInstance().jvm->GetEnv(reinterpret_cast<void**>(&testEnv), JNI_VERSION_1_6) == JNI_OK && testEnv != nullptr) {
                getInstance().jvm->DetachCurrentThread();
            }
            getInstance().jvmEnv = nullptr;
        }
        return getInstance().swapBuffersHook->getOriginal<swapBuffersSig>()(hdc);
    }

    if (getInstance().jvm && !getInstance().jvmEnv && !getInstance().shouldStop) {
        if (const jint result = getInstance().jvm->GetEnv(reinterpret_cast<void **>(&getInstance().jvmEnv), JNI_VERSION_1_6);
            result == JNI_EDETACHED) {
            getInstance().jvm->AttachCurrentThread(reinterpret_cast<void**>(&getInstance().jvmEnv), nullptr);
        }
    }

    const auto window = WindowFromDC(hdc);
    RECT rect;
    GetClientRect(window, &rect);

    if (update && !getInstance().shouldStop) {
        getInstance().drawing(rect);
    }

    return getInstance().swapBuffersHook->getOriginal<swapBuffersSig>()(hdc);
}

bool Gui::init() {
    this->openglDC = nullptr;
    this->openglRC = nullptr;

    const HMODULE gdiModule = GetModuleHandleA(Strings::gdi32Dll());
    if (!gdiModule) return false;

    const auto swapBuffersProc = GetProcAddress(gdiModule, Strings::swapBuffersFunc());
    if (!swapBuffersProc) return false;

    MH_STATUS mhStatus = MH_Initialize();
    if (mhStatus != MH_OK && mhStatus != MH_ERROR_ALREADY_INITIALIZED) return false;

    this->swapBuffersHook = new Hook(swapBuffersProc, this->swapBuffersProc);
    if (!this->swapBuffersHook->create()) return false;
    this->swapBuffersHook->enable();

    this->targetWindow = nullptr;
    {
        DWORD ourPid = GetCurrentProcessId();
        HWND candidate = nullptr;
        while ((candidate = FindWindowExA(nullptr, candidate, Strings::lwjglWindow(), nullptr)) != nullptr) {
            DWORD windowPid = 0;
            GetWindowThreadProcessId(candidate, &windowPid);
            if (windowPid == ourPid) {
                this->targetWindow = candidate;
                break;
            }
        }
    }
    if (!this->targetWindow) return false;

    this->lastWindowProc = SetWindowLongPtrA(this->targetWindow, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(windowProc));
    Size = { elements->window.size };
    const auto hdc = GetDC(this->targetWindow);
    if (!hdc) {
        return false;
    }

    this->openglDC = hdc;
    IMGUI_CHECKVERSION();
    CreateContext();
    ImGuiIO& io = GetIO(); (void)io;
    io.IniFilename = nullptr;
    StyleColorsClassic();
    ImGui_ImplWin32_InitForOpenGL(this->targetWindow);
    ImGui_ImplOpenGL2_Init();

    font->preload_all();

    return true;
}

void Gui::drawing(const RECT rect) const {
    if (this->screenType == NONE)
        return;

    auto& io = ImGui::GetIO();
    io.DisplaySize.x = static_cast<float>(rect.right - rect.left);
    io.DisplaySize.y = static_cast<float>(rect.bottom - rect.top);

    if (var->gui.dpi_changed)
    {
        return;
    }

    ImGui_ImplOpenGL2_NewFrame();
    ImGui_ImplWin32_NewFrame();
    NewFrame();

    widgets->close_all_popups();
    if (!this->open) slider_edit_force_exit();
    gui->initialize();

    gui->easing(var->gui.alpha, var->gui.tab != var->gui.stored ? 0.f : 1.f, 6.f, linear_easing);
    if (var->gui.alpha < 0.01f)
    {
        var->gui.tab = var->gui.stored;
    }

    if (this->enableGui) {
        if (this->open) {
            static ImVec2 guiPos    = {-1.f, -1.f};
            static bool   guiDrag   = false;
            static ImVec2 guiDragOff;

            const float sw = io.DisplaySize.x;
            const float sh = io.DisplaySize.y;
            const ImVec2 winSize = SCALE(elements->window.size);
            const float  tbH     = SCALE(elements->titlebar.size).y;

            if (guiPos.x < 0.f)
                guiPos = { sw * 0.5f - winSize.x * 0.5f, sh * 0.5f - winSize.y * 0.5f };

            gui->set_next_window_pos(guiPos, gui_cond_always);
            gui->set_next_window_size(winSize);
            gui->begin(Strings::windowTitle(), nullptr, window_flags_no_background | window_flags_no_decoration | window_flags_no_focus_on_appearing | window_flags_no_bring_to_front_on_focus | window_flags_no_scroll_with_mouse | window_flags_no_scrollbar | window_flags_no_move);
            {
                gui->set_style();
                gui->draw_decorations();

                gui->begin_content(Strings::titlebarId(), SCALE(elements->titlebar.size), SCALE(0, 0), SCALE(0, 0), window_flags_no_scroll_with_mouse | window_flags_no_scrollbar);
                {
                    const ImRect imRect = gui->get_window()->Rect();
                    ImDrawList* drawlist = gui->get_window()->DrawList;
                    draw->rect_filled(drawlist, imRect.Min, imRect.Max, draw->get_clr(clr->child),
                                      SCALE(elements->window.rounding), draw_flags_round_corners_top);

                    draw->text_clipped(drawlist, font->get(icon_font, 10),
                                       imRect.Min + SCALE(elements->padding.x, 0), imRect.Max,
                                       draw->get_clr(clr->accent), Strings::iconText(), nullptr, nullptr, {0, 0.5});

                    draw->text_clipped(drawlist, font->get(my_font, 12),
                                       imRect.Min + SCALE(elements->padding.x * 3, 0), imRect.Max,
                                       draw->get_clr(clr->accent), Strings::windowTitle(), nullptr, nullptr, {0, 0.5});

                    std::string displayText;

                    if (auto* authSvc = ClientMain::getInstance().getAuthService()) {
                        if (auto* session = authSvc->currentSession()) {
                            displayText = session->username.data;
                        }
                    }
                    displayText += Strings::lifetimeSuffix();
                    draw->text_clipped(drawlist, font->get(my_font, 12), imRect.Min, imRect.Max - SCALE(elements->padding.x, 0),
                    draw->get_clr(clr->text_inactive), displayText.c_str() , nullptr, nullptr, { 1, 0.5 });
                    secureErase(displayText);
                }
                gui->end_content();

                {
                    const ImVec2 mouse   = ImGui::GetMousePos();
                    const bool   down    = ImGui::IsMouseDown(0);
                    const bool   clicked = ImGui::IsMouseClicked(0);
                    const bool   inTb    = mouse.x >= guiPos.x && mouse.x <= guiPos.x + winSize.x
                                        && mouse.y >= guiPos.y && mouse.y <= guiPos.y + tbH;
                    if (clicked && inTb) {
                        guiDrag    = true;
                        guiDragOff = ImVec2(guiPos.x - mouse.x, guiPos.y - mouse.y);
                    }
                    if (!down) guiDrag = false;
                    if (guiDrag && down) {
                        guiPos.x = std::max(0.f, std::min(mouse.x + guiDragOff.x, sw - winSize.x));
                        guiPos.y = std::max(0.f, std::min(mouse.y + guiDragOff.y, sh - winSize.y));
                    }
                }

                std::vector<CategoryType> orderedCategories;
                for (int i = 0; i < static_cast<int>(CategoryType::CATEGORY_COUNT); ++i) {
                    auto category = static_cast<CategoryType>(i);
                    if (category == CategoryType::BACKEND) {
                        continue;
                    }
                    orderedCategories.push_back(category);
                }

                gui->begin_content(Strings::sidebarId(), SCALE(elements->sidebar.size), SCALE(elements->padding), SCALE(elements->padding));
                {
                    int startIndex = 0;
                    for (const auto& category : orderedCategories) {
                        auto categoryModules = ModuleHandler::getInstance().getModulesByCategory(category);
                        if (categoryModules.empty()) {
                            continue;
                        }

                        {
                            std::vector<DynamicTrackedString> trackedModuleNames;
                            trackedModuleNames.reserve(categoryModules.size());
                            std::vector<int> indices;
                            indices.reserve(categoryModules.size());

                            for (const auto& module : categoryModules) {
                                trackedModuleNames.emplace_back(toName(module->getType()));
                            }

                            for (int i = 0; i < trackedModuleNames.size(); i++) {
                                indices.push_back(startIndex + i);
                            }

                            const char* categoryName = toName(category);
                            std::vector<const char*> tempPtrs;
                            tempPtrs.reserve(trackedModuleNames.size());
                            for (const auto& tracked : trackedModuleNames) {
                                tempPtrs.push_back(tracked.c_str());
                            }
                            widgets->tab_section(categoryName, tempPtrs, indices);

                            startIndex += trackedModuleNames.size();
                        }
                    }
                }
                gui->end_content();
                gui->sameline();

                gui->push_var(style_var_alpha, var->gui.alpha);
                gui->begin_content(Strings::contentId(), SCALE(elements->content.size), SCALE(0, elements->padding.y), SCALE(elements->padding), window_flags_no_move);
                {
                    if (const IScreen* screen = getScreen(this->screenType)) {
                        screen->drawing(rect, this);
                    }
                }
                gui->end_content();

                gui->pop_var();
            }
            gui->end();
        }
    }

    EventBus& eventBus = EventBus::getInstance();
    const Render2dEvent render2dEvent(jvmEnv, 0.0f);
    eventBus.dispatch(render2dEvent);

    if (open == false) {
        const Render3dEvent render3dEvent(jvmEnv, 0.0f);
        eventBus.dispatch(render3dEvent);
    }

    EndFrame();
    Render();
    ImGui_ImplOpenGL2_RenderDrawData(GetDrawData());
}

DWORD WINAPI Gui::loop(LPVOID param) {
    update = true;

    getInstance().addScreen(std::make_unique<ModuleScreen>());

    getInstance().init();
    getInstance().isRunning = true;

    while (!getInstance().shouldStop) {
        Sleep(100);

        HWND window = nullptr;
        DWORD ourPid = GetCurrentProcessId();
        HWND candidate = nullptr;
        while ((candidate = FindWindowExA(nullptr, candidate, Strings::lwjglWindow(), nullptr)) != nullptr) {
            DWORD windowPid = 0;
            GetWindowThreadProcessId(candidate, &windowPid);
            if (windowPid == ourPid) {
                window = candidate;
                break;
            }
        }
        if (!window || !IsWindow(window)) {
            continue;
        }

        if (getInstance().targetWindow == window) continue;

        SetWindowLongPtrA(getInstance().targetWindow, GWLP_WNDPROC, getInstance().lastWindowProc);
        getInstance().targetWindow = window;
        getInstance().lastWindowProc = SetWindowLongPtrA(window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(windowProc));

        update = false;

        ImGui_ImplWin32_Shutdown();
        ImGui_ImplOpenGL2_Shutdown();

        ImGui_ImplWin32_InitForOpenGL(getInstance().targetWindow);
        ImGui_ImplOpenGL2_Init();

        update = true;
    }

    getInstance().clear();
    getInstance().isRunning = false;

    return 0;
}

bool Gui::clear() {
    if (this->swapBuffersHook) {
        this->swapBuffersHook->disable();
        this->swapBuffersHook->remove();
    }

    HWND windowForCleanup = this->targetWindow;

    if (this->targetWindow && this->lastWindowProc) {
        SetWindowLongPtrA(this->targetWindow, GWLP_WNDPROC, this->lastWindowProc);
    }

    if (ImGui::GetCurrentContext()) {

        ImGuiContext* ctx = ImGui::GetCurrentContext();
        if (ctx) {

            ImGui::ClearActiveID();

            for (ImGuiWindow* window : ctx->Windows) {
                if (window && window->Name) {
                    size_t nameLen = strlen(window->Name);
                    SecureZeroMemory((void*)window->Name, nameLen);
                }
            }
        }

        ImGui_ImplWin32_Shutdown();
        ImGui_ImplOpenGL2_Shutdown();
        DestroyContext();
    }

    if (this->openglRC) {
        wglMakeCurrent(nullptr, nullptr);
        wglDeleteContext(this->openglRC);
        this->openglRC = nullptr;
    }

    if (this->openglDC && windowForCleanup) {
        ReleaseDC(windowForCleanup, this->openglDC);
        this->openglDC = nullptr;
    }

    MH_Uninitialize();
    return true;
}

bool Gui::safeUnload() {
    this->shouldStop = true;

    int timeout = 100;
    while (this->isRunning && timeout > 0) {
        Sleep(100);
        timeout--;
    }

    if (this->isRunning) {
        return false;
    }

    if (this->swapBuffersHook) {
        this->swapBuffersHook->disable();
        this->swapBuffersHook->remove();
        delete this->swapBuffersHook;
        this->swapBuffersHook = nullptr;
    }

    HWND windowForCleanup = this->targetWindow;
    if (this->targetWindow && this->lastWindowProc) {
        SetWindowLongPtrA(this->targetWindow, GWLP_WNDPROC, this->lastWindowProc);
        Sleep(300);
        this->lastWindowProc = 0;
        this->targetWindow = nullptr;
    }

    if (GetCurrentContext()) {

        ImGuiContext* ctx = ImGui::GetCurrentContext();
        if (ctx) {

            ImGui::ClearActiveID();

            for (ImGuiWindow* window : ctx->Windows) {
                if (window && window->Name) {
                    size_t nameLen = strlen(window->Name);
                    SecureZeroMemory((void*)window->Name, nameLen);
                }
            }
        }

        ImGui_ImplWin32_Shutdown();
        ImGui_ImplOpenGL2_Shutdown();
        DestroyContext();
    }

    if (this->openglRC) {
        wglMakeCurrent(nullptr, nullptr);
        wglDeleteContext(this->openglRC);
        this->openglRC = nullptr;
    }

    if (this->openglDC && windowForCleanup) {
        ReleaseDC(windowForCleanup, this->openglDC);
        this->openglDC = nullptr;
    }

    MH_Uninitialize();

    Sleep(200);

    this->screens.clear();

    if (this->jvm && this->jvmEnv) {
        this->jvmEnv = nullptr;
    }

    this->open = false;
    this->enableGui = false;
    this->requestUnload = false;

    return true;
}

bool Gui::start() const {
    const_cast<Gui*>(this)->loopThreadHandle = CreateThread(nullptr, 0, Gui::loop, nullptr, 0, nullptr);
    return loopThreadHandle != nullptr;
}

bool Gui::stop() {
    this->shouldStop = true;

    int timeout = 100;
    while (this->isRunning && timeout > 0) {
        Sleep(100);
        timeout--;
    }

    if (loopThreadHandle != nullptr) {
        DWORD waitResult = WaitForSingleObject(loopThreadHandle, 5000);

        if (waitResult == WAIT_TIMEOUT) {
            TerminateThread(loopThreadHandle, 1);
        }

        CloseHandle(loopThreadHandle);
        loopThreadHandle = nullptr;
    }

    return true;
}

Gui& Gui::getInstance() {
    static Gui instance;
    return instance;
}
