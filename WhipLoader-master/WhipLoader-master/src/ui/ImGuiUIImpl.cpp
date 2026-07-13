#ifdef WHIP_UI_IMGUI

#include "ui/ImGuiUIImpl.h"

#include <windows.h>
#include <gl/GL.h>

#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_opengl3.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace {

enum class LogLevel { Status, Success, Error, Info, Warning };

struct LogLine {
    LogLevel level;
    std::string text;
};

struct ProgressState {
    bool active = false;
    std::string message;
    int percent = 0;
};

struct MenuState {
    bool active = false;
    std::string title;
    std::vector<MenuItem> items;
    int selectedId = -1;
    bool resolved = false;
};

struct InputState {
    bool active = false;
    std::string prompt;
    char buffer[512] = {0};
    std::string result;
    bool resolved = false;
};

struct KeyState {
    bool active = false;
    std::string message;
    bool resolved = false;
};

ImVec4 colorFor(LogLevel lvl) {
    switch (lvl) {
        case LogLevel::Success: return ImVec4(0.40f, 0.90f, 0.40f, 1.0f);
        case LogLevel::Error:   return ImVec4(0.95f, 0.35f, 0.35f, 1.0f);
        case LogLevel::Info:    return ImVec4(0.55f, 0.80f, 1.00f, 1.0f);
        case LogLevel::Warning: return ImVec4(1.00f, 0.80f, 0.30f, 1.0f);
        case LogLevel::Status:  default: return ImVec4(0.85f, 0.85f, 0.85f, 1.0f);
    }
}

} // namespace

struct ImGuiUIImpl::Impl {
    std::atomic<bool> initialized{false};
    std::atomic<bool> shouldStop{false};
    std::atomic<bool> renderReady{false};

    std::thread renderThread;

    HWND hwnd = nullptr;
    HDC  hdc  = nullptr;
    HGLRC hrc = nullptr;
    WNDCLASSEXW wc{};

    std::mutex mtx;
    std::condition_variable cv;

    std::deque<LogLine> log;
    bool showBannerFlag = false;

    ProgressState progress;
    MenuState menu;
    InputState input;
    KeyState keyWait;

    OnMenuSelected onMenuSelected;

    void pushLog(LogLevel lvl, const std::string& s) {
        std::lock_guard<std::mutex> lk(mtx);
        log.push_back({lvl, s});
        while (log.size() > 512) log.pop_front();
    }

    static LRESULT CALLBACK wndProc(HWND hWnd, UINT msg, WPARAM w, LPARAM l) {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, w, l)) return 1;
        switch (msg) {
            case WM_CLOSE:
            case WM_DESTROY:
                PostQuitMessage(0);
                return 0;
        }
        return DefWindowProcW(hWnd, msg, w, l);
    }

    bool createWindow() {
        wc = { sizeof(WNDCLASSEXW), CS_OWNDC, wndProc, 0, 0, GetModuleHandleW(nullptr),
               nullptr, LoadCursorW(nullptr, IDC_ARROW), nullptr, nullptr,
               L"WhipClientImGuiWnd", nullptr };
        if (!RegisterClassExW(&wc)) {
            wchar_t m[128]; wsprintfW(m, L"RegisterClassExW failed: %lu", GetLastError());
            MessageBoxW(nullptr, m, L"WhipClient GUI", MB_ICONERROR);
            return false;
        }

        hwnd = CreateWindowExW(0, wc.lpszClassName, L"WhipClient",
                               WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
                               CW_USEDEFAULT, CW_USEDEFAULT, 900, 600,
                               nullptr, nullptr, wc.hInstance, nullptr);
        if (!hwnd) {
            wchar_t m[128]; wsprintfW(m, L"CreateWindowExW failed: %lu", GetLastError());
            MessageBoxW(nullptr, m, L"WhipClient GUI", MB_ICONERROR);
            return false;
        }

        hdc = GetDC(hwnd);
        PIXELFORMATDESCRIPTOR pfd{};
        pfd.nSize = sizeof(pfd);
        pfd.nVersion = 1;
        pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
        pfd.iPixelType = PFD_TYPE_RGBA;
        pfd.cColorBits = 32;
        pfd.cDepthBits = 24;
        pfd.iLayerType = PFD_MAIN_PLANE;
        int pf = ChoosePixelFormat(hdc, &pfd);
        if (!pf || !SetPixelFormat(hdc, pf, &pfd)) {
            wchar_t m[128]; wsprintfW(m, L"Pixel format failed pf=%d err=%lu", pf, GetLastError());
            MessageBoxW(nullptr, m, L"WhipClient GUI", MB_ICONERROR);
            return false;
        }

        hrc = wglCreateContext(hdc);
        if (!hrc || !wglMakeCurrent(hdc, hrc)) {
            wchar_t m[128]; wsprintfW(m, L"wglCreateContext/MakeCurrent failed err=%lu", GetLastError());
            MessageBoxW(nullptr, m, L"WhipClient GUI", MB_ICONERROR);
            return false;
        }

        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        SetFocus(hwnd);
        UpdateWindow(hwnd);
        return true;
    }

    void destroyWindow() {
        if (hrc) { wglMakeCurrent(nullptr, nullptr); wglDeleteContext(hrc); hrc = nullptr; }
        if (hdc) { ReleaseDC(hwnd, hdc); hdc = nullptr; }
        if (hwnd) { DestroyWindow(hwnd); hwnd = nullptr; }
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
    }

    void drawBanner() {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.40f, 0.70f, 1.00f, 1.0f));
        ImGui::TextUnformatted("           _     _              _ _            _   ");
        ImGui::TextUnformatted("__      __| |__ (_)_ __     ___| (_) ___ _ __ | |_ ");
        ImGui::TextUnformatted("\\ \\ /\\ / /| '_ \\| | '_ \\   / __| | |/ _ \\ '_ \\| __|");
        ImGui::TextUnformatted(" \\ V  V / | | | | | |_) | | (__| | |  __/ | | | |_ ");
        ImGui::TextUnformatted("  \\_/\\_/  |_| |_|_| .__/   \\___|_|_|\\___|_| |_|\\__|");
        ImGui::TextUnformatted("                  |_|                              ");
        ImGui::PopStyleColor();
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.6f, 0.6f, 1.0f));
        ImGui::TextUnformatted("                                               b0.1");
        ImGui::PopStyleColor();
        ImGui::Separator();
    }

    void buildFrame() {
        const ImGuiViewport* vp = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(vp->WorkPos);
        ImGui::SetNextWindowSize(vp->WorkSize);
        ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove
                               | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings
                               | ImGuiWindowFlags_NoBringToFrontOnFocus;

        ImGui::Begin("WhipClient##root", nullptr, flags);

        std::unique_lock<std::mutex> lk(mtx);

        if (showBannerFlag) drawBanner();

        if (progress.active) {
            ImGui::TextUnformatted(progress.message.c_str());
            ImGui::ProgressBar(progress.percent / 100.0f, ImVec2(-1, 0), "");
            ImGui::Separator();
        }

        ImGui::BeginChild("##log", ImVec2(0, -120), true);
        for (const auto& line : log) {
            ImGui::PushStyleColor(ImGuiCol_Text, colorFor(line.level));
            ImGui::TextWrapped("%s", line.text.c_str());
            ImGui::PopStyleColor();
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 1.0f)
            ImGui::SetScrollHereY(1.0f);
        ImGui::EndChild();

        ImGui::Separator();

        if (menu.active) {
            ImGui::TextUnformatted(menu.title.c_str());
            for (const auto& it : menu.items) {
                std::string label = "[" + std::to_string(it.id) + "] " + it.label;
                if (ImGui::Button(label.c_str(), ImVec2(-1, 0))) {
                    menu.selectedId = it.id;
                    menu.resolved = true;
                    cv.notify_all();
                }
            }
        } else if (input.active) {
            ImGui::TextUnformatted(input.prompt.c_str());
            ImGui::SetNextItemWidth(-80);
            bool enter = ImGui::InputText("##inp", input.buffer, sizeof(input.buffer),
                                          ImGuiInputTextFlags_EnterReturnsTrue);
            ImGui::SameLine();
            if (ImGui::Button("OK") || enter) {
                input.result = input.buffer;
                input.resolved = true;
                cv.notify_all();
            }
        } else if (keyWait.active) {
            ImGui::TextUnformatted(keyWait.message.c_str());
            if (ImGui::Button("Continue", ImVec2(-1, 0))) {
                keyWait.resolved = true;
                cv.notify_all();
            }
        }

        lk.unlock();
        ImGui::End();
    }

    void renderLoop() {
        if (!createWindow()) {
            renderReady = true;
            return;
        }

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGui::StyleColorsDark();
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;

        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplOpenGL3_Init("#version 130");

        renderReady = true;

        MSG msg;
        while (!shouldStop.load()) {
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
                if (msg.message == WM_QUIT) shouldStop = true;
            }
            if (shouldStop) break;

            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            buildFrame();

            ImGui::Render();
            RECT rc; GetClientRect(hwnd, &rc);
            glViewport(0, 0, rc.right - rc.left, rc.bottom - rc.top);
            glClearColor(0.08f, 0.08f, 0.10f, 1.0f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
            SwapBuffers(hdc);
        }

        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        destroyWindow();

        std::lock_guard<std::mutex> lk(mtx);
        if (menu.active)    { menu.resolved    = true; }
        if (input.active)   { input.resolved   = true; }
        if (keyWait.active) { keyWait.resolved = true; }
        cv.notify_all();
    }
};

ImGuiUIImpl::ImGuiUIImpl() : impl_(std::make_unique<Impl>()) {}

ImGuiUIImpl::~ImGuiUIImpl() { shutdown(); }

VoidResult ImGuiUIImpl::initialize() {
    if (impl_->initialized.load()) return VoidResult::ok();
    impl_->shouldStop = false;
    impl_->renderReady = false;
    impl_->renderThread = std::thread([this]{ impl_->renderLoop(); });
    while (!impl_->renderReady.load()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    impl_->initialized = true;
    return VoidResult::ok();
}

void ImGuiUIImpl::shutdown() {
    if (!impl_->initialized.load()) return;
    impl_->shouldStop = true;
    if (impl_->hwnd) PostMessageW(impl_->hwnd, WM_CLOSE, 0, 0);
    if (impl_->renderThread.joinable()) impl_->renderThread.join();
    impl_->initialized = false;
}

bool ImGuiUIImpl::isInitialized() const noexcept { return impl_->initialized.load(); }

void ImGuiUIImpl::showBanner() {
    std::lock_guard<std::mutex> lk(impl_->mtx);
    impl_->showBannerFlag = true;
}

void ImGuiUIImpl::clearScreen() {
    std::lock_guard<std::mutex> lk(impl_->mtx);
    impl_->log.clear();
}

void ImGuiUIImpl::showStatus(const std::string& m)  { impl_->pushLog(LogLevel::Status,  m); }
void ImGuiUIImpl::showSuccess(const std::string& m) { impl_->pushLog(LogLevel::Success, m); }
void ImGuiUIImpl::showError(const std::string& m)   { impl_->pushLog(LogLevel::Error,   m); }
void ImGuiUIImpl::showInfo(const std::string& m)    { impl_->pushLog(LogLevel::Info,    m); }
void ImGuiUIImpl::showWarning(const std::string& m) { impl_->pushLog(LogLevel::Warning, m); }

void ImGuiUIImpl::showProgress(const std::string& m, int percent) {
    std::lock_guard<std::mutex> lk(impl_->mtx);
    impl_->progress.active = true;
    impl_->progress.message = m;
    impl_->progress.percent = percent < 0 ? 0 : (percent > 100 ? 100 : percent);
}

void ImGuiUIImpl::hideProgress() {
    std::lock_guard<std::mutex> lk(impl_->mtx);
    impl_->progress.active = false;
}

void ImGuiUIImpl::showMenu(const std::string& title, const std::vector<MenuItem>& items) {
    std::lock_guard<std::mutex> lk(impl_->mtx);
    impl_->menu.title = title;
    impl_->menu.items = items;
    impl_->menu.selectedId = -1;
    impl_->menu.resolved = false;
    impl_->menu.active = true;
}

int ImGuiUIImpl::waitForMenuSelection(int minId, int maxId) {
    std::unique_lock<std::mutex> lk(impl_->mtx);
    impl_->cv.wait(lk, [&]{
        return impl_->menu.resolved
               && impl_->menu.selectedId >= minId
               && impl_->menu.selectedId <= maxId;
    });
    int sel = impl_->menu.selectedId;
    impl_->menu.active = false;
    auto cb = impl_->onMenuSelected;
    lk.unlock();
    if (cb) cb(sel);
    return sel;
}

int ImGuiUIImpl::showArrowSelectionMenu(const std::vector<MenuItem>& items) {
    if (items.empty()) return -1;
    showMenu("Select", items);
    std::unique_lock<std::mutex> lk(impl_->mtx);
    impl_->cv.wait(lk, [&]{ return impl_->menu.resolved; });
    int sel = impl_->menu.selectedId;
    impl_->menu.active = false;
    int index = 0;
    for (size_t i = 0; i < items.size(); ++i) {
        if (items[i].id == sel) { index = static_cast<int>(i); break; }
    }
    auto cb = impl_->onMenuSelected;
    lk.unlock();
    if (cb) cb(sel);
    return index;
}

std::string ImGuiUIImpl::waitForInput(const std::string& prompt) {
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        impl_->input.prompt = prompt;
        impl_->input.buffer[0] = '\0';
        impl_->input.result.clear();
        impl_->input.resolved = false;
        impl_->input.active = true;
    }
    std::unique_lock<std::mutex> lk(impl_->mtx);
    impl_->cv.wait(lk, [&]{ return impl_->input.resolved; });
    std::string r = impl_->input.result;
    impl_->input.active = false;
    return r;
}

void ImGuiUIImpl::waitForKey(const std::string& message) {
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        impl_->keyWait.message = message;
        impl_->keyWait.resolved = false;
        impl_->keyWait.active = true;
    }
    std::unique_lock<std::mutex> lk(impl_->mtx);
    impl_->cv.wait(lk, [&]{ return impl_->keyWait.resolved; });
    impl_->keyWait.active = false;
}

void ImGuiUIImpl::setOnMenuSelected(OnMenuSelected callback) {
    std::lock_guard<std::mutex> lk(impl_->mtx);
    impl_->onMenuSelected = std::move(callback);
}

void ImGuiUIImpl::hideWindow() {
    if (impl_->hwnd) ShowWindow(impl_->hwnd, SW_HIDE);
}

void ImGuiUIImpl::showWindow() {
    if (impl_->hwnd) {
        ShowWindow(impl_->hwnd, SW_SHOW);
        SetWindowPos(impl_->hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        SetWindowPos(impl_->hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        SetForegroundWindow(impl_->hwnd);
    }
}

#endif // WHIP_UI_IMGUI
