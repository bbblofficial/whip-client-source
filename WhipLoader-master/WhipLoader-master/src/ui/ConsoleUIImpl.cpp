#include "ui/ConsoleUIImpl.h"
#include "util/ConsoleUtils.h"

#include <Windows.h>
#include <dwmapi.h>
#include <VersionHelpers.h>
#include <cstdarg>
#include <iostream>
#include <fcntl.h>
#include <string>
#include <limits>
#include <thread>
#include <chrono>

#pragma comment(lib, "dwmapi.lib")

#ifndef ENABLE_QUICK_EDIT_MODE
#define ENABLE_QUICK_EDIT_MODE 0x0040
#endif

#ifndef ENABLE_EXTENDED_FLAGS
#define ENABLE_EXTENDED_FLAGS 0x0080
#endif

#ifndef ENABLE_MOUSE_INPUT
#define ENABLE_MOUSE_INPUT 0x0010
#endif

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

enum class ConsoleColor : WORD {
    Black       = 0,
    DarkBlue    = FOREGROUND_BLUE,
    DarkGreen   = FOREGROUND_GREEN,
    DarkCyan    = FOREGROUND_GREEN | FOREGROUND_BLUE,
    DarkRed     = FOREGROUND_RED,
    DarkMagenta = FOREGROUND_RED | FOREGROUND_BLUE,
    DarkYellow  = FOREGROUND_RED | FOREGROUND_GREEN,
    Gray        = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
    DarkGray    = FOREGROUND_INTENSITY,
    Blue        = FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    Green       = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    Cyan        = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    Red         = FOREGROUND_RED | FOREGROUND_INTENSITY,
    Magenta     = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    Yellow      = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    White       = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY
};


struct ConsoleUIImpl::Impl {
    HANDLE hConsole = INVALID_HANDLE_VALUE;
    HANDLE hInput = INVALID_HANDLE_VALUE;
    CONSOLE_SCREEN_BUFFER_INFO originalInfo{};
    DWORD originalInputMode = 0;
    bool initialized = false;
    OnMenuSelected onMenuSelected;

    bool progressActive = false;
    COORD progressPos = {0, 0};

    void setColor(ConsoleColor color) {
        SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
    }

    void resetColor() {
        SetConsoleTextAttribute(hConsole, originalInfo.wAttributes);
    }

    void disableSelection() {
        hInput = GetStdHandle(STD_INPUT_HANDLE);
        if (hInput != INVALID_HANDLE_VALUE) {
            GetConsoleMode(hInput, &originalInputMode);

            DWORD newMode = originalInputMode;
            newMode &= ~ENABLE_QUICK_EDIT_MODE;
            // Keep mouse input enabled for scrolling
            // newMode &= ~ENABLE_MOUSE_INPUT;
            newMode |= ENABLE_EXTENDED_FLAGS;
            SetConsoleMode(hInput, newMode);

            HWND consoleWnd = GetConsoleWindow();
            if (consoleWnd) {
                HMENU hMenu = GetSystemMenu(consoleWnd, FALSE);
                if (hMenu) {
                    // DeleteMenu(hMenu, SC_CLOSE, MF_BYCOMMAND);
                    // EnableMenuItem(hMenu, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
                }
            }
        }
    }

    void hideCursor() {
        CONSOLE_CURSOR_INFO cursorInfo;
        GetConsoleCursorInfo(hConsole, &cursorInfo);
        cursorInfo.bVisible = FALSE;
        SetConsoleCursorInfo(hConsole, &cursorInfo);
    }

    void showCursor() {
        CONSOLE_CURSOR_INFO cursorInfo;
        GetConsoleCursorInfo(hConsole, &cursorInfo);
        cursorInfo.bVisible = TRUE;
        SetConsoleCursorInfo(hConsole, &cursorInfo);
    }

    void printCentered(const std::string& text) {
        int width = getConsoleWidth();
        int textLen = static_cast<int>(text.length());
        int padding = (width - textLen) / 2;
        if (padding < 0) padding = 0;
        std::cout << std::string(padding, ' ') << text << std::endl;
    }

    void clearLine() {
        int width = getConsoleWidth();
        std::cout << "\r" << std::string(width - 1, ' ') << "\r" << std::flush;
    }

    void setConsoleFont() {
        CONSOLE_FONT_INFOEX cfi;
        cfi.cbSize = sizeof(cfi);
        cfi.nFont = 0;
        cfi.dwFontSize.X = 0;
        cfi.dwFontSize.Y = 18;
        cfi.FontFamily = FF_DONTCARE;
        cfi.FontWeight = FW_NORMAL;

        wcscpy_s(cfi.FaceName, L"Cascadia Code");
        if (!SetCurrentConsoleFontEx(hConsole, FALSE, &cfi)) {
            wcscpy_s(cfi.FaceName, L"Lucida Console");
            SetCurrentConsoleFontEx(hConsole, FALSE, &cfi);
        }
    }

    void writeWide(const std::wstring& text) {
        DWORD written;
        WriteConsoleW(hConsole, text.c_str(), static_cast<DWORD>(text.length()), &written, NULL);
    }

    void setupConsoleWindow() {
        HWND consoleWindow = GetConsoleWindow();
        if (consoleWindow) {
            SetWindowDisplayAffinity(consoleWindow, WDA_EXCLUDEFROMCAPTURE);

            LONG style = GetWindowLong(consoleWindow, GWL_STYLE);
            style &= ~WS_MAXIMIZEBOX;
            style &= ~WS_SIZEBOX;
            SetWindowLong(consoleWindow, GWL_STYLE, style);

            CONSOLE_SCREEN_BUFFER_INFO csbi;
            GetConsoleScreenBufferInfo(hConsole, &csbi);
            COORD bufferSize;
            bufferSize.X = csbi.srWindow.Right - csbi.srWindow.Left + 1;
            bufferSize.Y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
            SetConsoleScreenBufferSize(hConsole, bufferSize);

            int screenWidth = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);

            RECT rect;
            GetWindowRect(consoleWindow, &rect);
            int windowWidth = rect.right - rect.left;
            int windowHeight = rect.bottom - rect.top;

            int x = (screenWidth - windowWidth) / 2;
            int y = (screenHeight - windowHeight) / 2;

            SetWindowPos(consoleWindow, HWND_TOP, x, y, 0, 0,
                         SWP_NOSIZE | SWP_FRAMECHANGED | SWP_SHOWWINDOW);
        }
    }

    int getConsoleWidth() {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
            return csbi.srWindow.Right - csbi.srWindow.Left + 1;
        }
        return 80;
    }

    int getConsoleHeight() {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
            return csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        }
        return 25;
    }

    void restoreInputMode() {
        if (hInput != INVALID_HANDLE_VALUE) {
            SetConsoleMode(hInput, originalInputMode);
        }
    }
};

// Local raw logger duplicated so this TU can write to the bisect log.
static void cuiBisectLog(const char* fmt, ...) { (void)fmt; }

ConsoleUIImpl::ConsoleUIImpl() {
    cuiBisectLog("ConsoleUIImpl ctor: enter (this=%p)", this);
    impl_ = std::make_unique<Impl>();
    cuiBisectLog("ConsoleUIImpl ctor: Impl made (impl_=%p)", impl_.get());
}

ConsoleUIImpl::~ConsoleUIImpl() {
    shutdown();
}

VoidResult ConsoleUIImpl::initialize() {
    impl_->hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (impl_->hConsole == INVALID_HANDLE_VALUE) {
        return VoidResult::err(ErrorCode::Unknown, "Failed to get console handle");
    }

    GetConsoleScreenBufferInfo(impl_->hConsole, &impl_->originalInfo);

    SetConsoleOutputCP(CP_UTF8);

    impl_->setConsoleFont();

    impl_->setupConsoleWindow();
    impl_->disableSelection();
    impl_->hideCursor();

    SetConsoleTitleW(L"WhipClient");

    impl_->disableSelection();

    impl_->initialized = true;

    return VoidResult::ok();
}

void ConsoleUIImpl::shutdown() {
    if (impl_->initialized) {
        impl_->restoreInputMode();
        impl_->resetColor();
        impl_->initialized = false;
    }
}

bool ConsoleUIImpl::isInitialized() const noexcept {
    return impl_->initialized;
}

void ConsoleUIImpl::showBanner() {
    clearScreen();

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    int width = 80;
    if (GetConsoleScreenBufferInfo(impl_->hConsole, &csbi)) {
        width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    }

    // Figlet block is 52 columns wide. Use \n-separated output with a fixed
    // left pad so the banner renders correctly even when the console handle
    // is a redirected stream or a buffer that rejects SetConsoleCursorPosition
    // (observed when the loader is manual-mapped into a host process and
    // inherits Lunar's console).
    constexpr int kBannerWidth = 52;
    int leftPad = (width - kBannerWidth) / 2;
    if (leftPad < 0) leftPad = 0;
    std::string pad(static_cast<size_t>(leftPad), ' ');

    // Top spacing — matches the original Y=6 cursor placement so the banner
    // sits roughly a third of the way down the screen instead of hugging the
    // top edge.
    std::cout << "\n\n\n\n\n\n";

    impl_->setColor(ConsoleColor::Blue);
    std::cout
        << pad << "           _     _              _ _            _   \n"
        << pad << "__      __| |__ (_)_ __     ___| (_) ___ _ __ | |_ \n"
        << pad << "\\ \\ /\\ / /| '_ \\| | '_ \\   / __| | |/ _ \\ '_ \\| __|\n"
        << pad << " \\ V  V / | | | | | |_) | | (__| | |  __/ | | | |_ \n"
        << pad << "  \\_/\\_/  |_| |_|_| .__/   \\___|_|_|\\___|_| |_|\\__|\n"
        << pad << "                  |_|                              \n";

    // Version label, right-aligned to the banner's right edge.
    impl_->setColor(ConsoleColor::DarkGray);
    const std::string label = "b0.1";
    int rightPad = kBannerWidth - static_cast<int>(label.length());
    if (rightPad < 0) rightPad = 0;
    std::cout
        << "\n"
        << pad << std::string(static_cast<size_t>(rightPad), ' ') << label << "\n\n";

    impl_->resetColor();
    std::cout << std::flush;
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

void ConsoleUIImpl::clearScreen() {
    COORD topLeft = {0, 0};
    DWORD written;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(impl_->hConsole, &csbi);
    DWORD size = csbi.dwSize.X * csbi.dwSize.Y;
    FillConsoleOutputCharacterW(impl_->hConsole, L' ', size, topLeft, &written);
    FillConsoleOutputAttribute(impl_->hConsole, impl_->originalInfo.wAttributes, size, topLeft, &written);
    SetConsoleCursorPosition(impl_->hConsole, topLeft);
}

void ConsoleUIImpl::showStatus(const std::string& message) {
    impl_->clearLine();
    impl_->setColor(ConsoleColor::Gray);
    impl_->printCentered("[*] " + message);
    impl_->resetColor();
}

void ConsoleUIImpl::showSuccess(const std::string& message) {
    //Utils::showSuccess(message);
}

void ConsoleUIImpl::showError(const std::string& message) {
    impl_->clearLine();
    impl_->setColor(ConsoleColor::Red);
    impl_->printCentered("[!] " + message);
    impl_->resetColor();
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

void ConsoleUIImpl::showInfo(const std::string& message) {
    // Print to stdout so [INJECT] traces from stepInject() show up in
    // the dev console — previously a no-op which made debugging the
    // inject path impossible without an ImGui build.
    std::cout << message << std::endl;
}

void ConsoleUIImpl::showWarning(const std::string& message) {
    std::cout << "[WARN] " << message << std::endl;
}

void ConsoleUIImpl::showProgress(const std::string& message, int percent) {
    int consoleWidth = impl_->getConsoleWidth();
    const int barWidth = 65;  // Same as banner width

    int padding = (consoleWidth - barWidth) / 2;
    if (padding < 0) padding = 0;

    if (!impl_->progressActive) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(impl_->hConsole, &csbi);
        impl_->progressPos = csbi.dwCursorPosition;
        impl_->progressActive = true;
    }

    SetConsoleCursorPosition(impl_->hConsole, impl_->progressPos);

    // Fractional blocks for smooth animation
    const wchar_t blocks[] = {
        L' ',
        L'\x258F',  // ▏ 1/8
        L'\x258E',  // ▎ 2/8
        L'\x258D',  // ▍ 3/8
        L'\x258C',  // ▌ 4/8
        L'\x258B',  // ▋ 5/8
        L'\x258A',  // ▊ 6/8
        L'\x2589',  // ▉ 7/8
        L'\x2588'   // █ 8/8
    };

    float progress = (percent / 100.0f) * barWidth;
    int fullBlocks = static_cast<int>(progress);
    int fraction = static_cast<int>((progress - fullBlocks) * 8);

    // Left padding (same as banner)
    impl_->writeWide(std::wstring(padding, L' '));

    // Write each block with color
    for (int i = 0; i < barWidth; ++i) {
        wchar_t ch;
        if (i < fullBlocks) {
            impl_->setColor(ConsoleColor::Blue);
            ch = blocks[8];
        } else if (i == fullBlocks && fraction > 0) {
            impl_->setColor(ConsoleColor::Blue);
            ch = blocks[fraction];
        } else {
            ch = L' ';
        }
        impl_->writeWide(std::wstring(1, ch));
    }

    impl_->writeWide(L"\n");

    // Empty line for spacing
    impl_->writeWide(L"\n");

    // Message centered below (without percentage)
    if (!message.empty()) {
        std::wstring messageStr;
        for (char c : message) messageStr += static_cast<wchar_t>(c);

        int textPadding = (consoleWidth - static_cast<int>(messageStr.length())) / 2;
        if (textPadding < 0) textPadding = 0;

        impl_->setColor(ConsoleColor::Gray);
        impl_->writeWide(std::wstring(textPadding, L' ') + messageStr + std::wstring(20, L' '));
        impl_->resetColor();
    }
}

void ConsoleUIImpl::hideProgress() {
    if (impl_->progressActive) {
        SetConsoleCursorPosition(impl_->hConsole, impl_->progressPos);

        int consoleWidth = impl_->getConsoleWidth();
        // Clear 3 lines: progress bar + empty line + message
        for (int i = 0; i < 3; ++i) {
            impl_->writeWide(std::wstring(consoleWidth, L' ') + L"\n");
        }

        SetConsoleCursorPosition(impl_->hConsole, impl_->progressPos);
        impl_->progressActive = false;
        impl_->progressPos = {0, 0};
    }
}

void ConsoleUIImpl::showMenu(const std::string& title, const std::vector<MenuItem>& items) {
    std::cout << std::endl;

    impl_->setColor(ConsoleColor::White);
    impl_->printCentered("=== " + title + " ===");
    impl_->resetColor();

    std::cout << std::endl;

    for (const auto& item : items) {
        std::string line = "[" + std::to_string(item.id) + "] " + item.label;
        if (!item.description.empty()) {
            line += " - " + item.description;
        }
        impl_->setColor(ConsoleColor::Cyan);
        impl_->printCentered(line);
        impl_->resetColor();
    }

    std::cout << std::endl;
}

int ConsoleUIImpl::waitForMenuSelection(int minId, int maxId) {
    int selection = -1;
    int consoleWidth = impl_->getConsoleWidth();
    std::string prompt = "Select [" + std::to_string(minId) + "-" + std::to_string(maxId) + "]: ";
    int padding = (consoleWidth - static_cast<int>(prompt.length()) - 5) / 2;
    if (padding < 0) padding = 0;

    while (selection < minId || selection > maxId) {
        impl_->setColor(ConsoleColor::Yellow);
        std::cout << std::string(padding, ' ') << prompt;
        impl_->resetColor();

        std::cin >> selection;

        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            selection = -1;
            showError("Invalid input. Please enter a number.");
        } else if (selection < minId || selection > maxId) {
            showError("Invalid selection. Please try again.");
        }
    }

    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    if (impl_->onMenuSelected) {
        impl_->onMenuSelected(selection);
    }

    return selection;
}

std::string ConsoleUIImpl::waitForInput(const std::string& prompt) {
    int consoleWidth = impl_->getConsoleWidth();
    int padding = (consoleWidth - static_cast<int>(prompt.length()) - 20) / 2;
    if (padding < 0) padding = 0;

    impl_->setColor(ConsoleColor::Yellow);
    std::cout << std::string(padding, ' ') << prompt;
    impl_->resetColor();

    std::string input;
    std::getline(std::cin, input);

    return input;
}

void ConsoleUIImpl::waitForKey(const std::string& message) {
    impl_->resetColor();
    std::cout << std::endl;
    impl_->printCentered(message);

    // Flush any buffered input events then wait for a real keypress
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    FlushConsoleInputBuffer(hInput);
    INPUT_RECORD ir;
    DWORD read;
    while (true) {
        ReadConsoleInput(hInput, &ir, 1, &read);
        if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
            break;
        }
    }
}

void ConsoleUIImpl::setOnMenuSelected(OnMenuSelected callback) {
    impl_->onMenuSelected = std::move(callback);
}

void ConsoleUIImpl::hideWindow() {
    if (HWND h = GetConsoleWindow()) ShowWindow(h, SW_HIDE);
}

void ConsoleUIImpl::showWindow() {
    if (HWND h = GetConsoleWindow()) {
        ShowWindow(h, SW_SHOW);
        SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        SetWindowPos(h, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        SetForegroundWindow(h);
    }
}

int ConsoleUIImpl::showArrowSelectionMenu(const std::vector<MenuItem>& items) {
    if (items.empty()) return -1;

    int selected = 0;
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);

    // Save cursor position
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(impl_->hConsole, &csbi);
    COORD startPos = csbi.dwCursorPosition;
    int consoleWidth = impl_->getConsoleWidth();

    auto renderMenu = [&]() {
        for (size_t i = 0; i < items.size(); ++i) {
            const auto& item = items[i];
            std::string line;

            if (i == static_cast<size_t>(selected)) {
                // Selected item - highlighted
                line = "> " + item.label;
                impl_->setColor(ConsoleColor::Cyan);
            } else {
                // Unselected item
                line = "  " + item.label;
                impl_->setColor(ConsoleColor::Gray);
            }

            // Position cursor at start of line (X=0)
            COORD linePos = {0, static_cast<SHORT>(startPos.Y + i)};
            SetConsoleCursorPosition(impl_->hConsole, linePos);

            // Clear the entire line
            impl_->writeWide(std::wstring(consoleWidth, L' '));

            // Reposition cursor at start of line
            SetConsoleCursorPosition(impl_->hConsole, linePos);

            // Center the line
            int padding = (consoleWidth - static_cast<int>(line.length())) / 2;
            if (padding < 0) padding = 0;

            std::cout << std::string(padding, ' ') << line << std::flush;
        }
        impl_->resetColor();
    };

    // Initial render
    renderMenu();

    // Input loop
    while (true) {
        INPUT_RECORD ir;
        DWORD read;
        ReadConsoleInput(hInput, &ir, 1, &read);

        if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
            switch (ir.Event.KeyEvent.wVirtualKeyCode) {
                case VK_UP:
                case 'W':  // QWERTY up
                case 'Z':  // AZERTY up
                case 'K':  // Vim-style up
                    selected--;
                    if (selected < 0) selected = static_cast<int>(items.size()) - 1;
                    renderMenu();
                    break;

                case VK_DOWN:
                case 'S':  // QWERTY/AZERTY down (same key)
                case 'J':  // Vim-style down
                    selected++;
                    if (selected >= static_cast<int>(items.size())) selected = 0;
                    renderMenu();
                    break;

                case VK_RETURN:
                case VK_SPACE: {  // Space as alternative confirm
                    // Clear all menu lines
                    for (size_t i = 0; i < items.size(); ++i) {
                        COORD linePos = {0, static_cast<SHORT>(startPos.Y + i)};
                        SetConsoleCursorPosition(impl_->hConsole, linePos);
                        impl_->writeWide(std::wstring(consoleWidth, L' '));
                    }

                    // Move cursor back to start position
                    SetConsoleCursorPosition(impl_->hConsole, startPos);

                    if (impl_->onMenuSelected) {
                        impl_->onMenuSelected(items[selected].id);
                    }
                    return selected;
                }

                default:
                    break;
            }
        }
    }
}
