#pragma once

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <windows.h>
#include <tlhelp32.h>

namespace Utils {

    inline void hideScrollbar() {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);

        COORD newSize;
        newSize.X = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        newSize.Y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        SetConsoleScreenBufferSize(hConsole, newSize);
    }

    inline void setConsoleSize(int width, int height) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        // Set buffer size first
        COORD bufferSize;
        bufferSize.X = static_cast<SHORT>(width);
        bufferSize.Y = static_cast<SHORT>(height);
        SetConsoleScreenBufferSize(hConsole, bufferSize);

        // Set window size
        SMALL_RECT windowSize;
        windowSize.Left = 0;
        windowSize.Top = 0;
        windowSize.Right = static_cast<SHORT>(width - 1);
        windowSize.Bottom = static_cast<SHORT>(height - 1);
        SetConsoleWindowInfo(hConsole, TRUE, &windowSize);
    }

    inline void createConsole() {
        AllocConsole();

        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        freopen_s(&fp, "CONIN$", "r", stdin);

        // Hide scrollbars
        hideScrollbar();
    }

    inline void hideCursor() {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_CURSOR_INFO cursorInfo;
        GetConsoleCursorInfo(hConsole, &cursorInfo);
        cursorInfo.bVisible = FALSE;
        SetConsoleCursorInfo(hConsole, &cursorInfo);
    }

    inline void disableResize() {
        HWND consoleWindow = GetConsoleWindow();
        LONG style = GetWindowLong(consoleWindow, GWL_STYLE);
        style &= ~(WS_SIZEBOX | WS_MAXIMIZEBOX);
        SetWindowLong(consoleWindow, GWL_STYLE, style);
    }

    inline void enableScreenCaptureProtection() {
        HWND consoleWindow = GetConsoleWindow();
        SetWindowDisplayAffinity(consoleWindow, WDA_EXCLUDEFROMCAPTURE);
    }

    inline void disableConsoleSelection() {
        HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode;
        GetConsoleMode(hConsole, &mode);

        mode &= ~ENABLE_QUICK_EDIT_MODE;
        mode &= ~ENABLE_INSERT_MODE;
        mode &= ~ENABLE_MOUSE_INPUT;

        SetConsoleMode(hConsole, mode);
    }

    inline void setColor(int color) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<WORD>(color));
    }

    inline void clearScreen() {
        system("cls");
    }

    inline void setCursorPosition(int x, int y) {
        COORD coord;
        coord.X = static_cast<SHORT>(x);
        coord.Y = static_cast<SHORT>(y);
        SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coord);
    }

    inline void printCentered(const std::string& text, int y, int color) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        int width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        int x = (width - static_cast<int>(text.length())) / 2;
        setCursorPosition(x, y);
        setColor(color);
        std::cout << text;
    }

    inline void printLogo() {
        clearScreen();

        setColor(9);

        printCentered("           _     _              _ _            _   ", 6, 9);
        printCentered("__      __| |__ (_)_ __     ___| (_) ___ _ __ | |_ ", 7, 9);
        printCentered("\\ \\ /\\ / /| '_ \\| | '_ \\   / __| | |/ _ \\ '_ \\| __|", 8, 9);
        printCentered(" \\ V  V / | | | | | |_) | | (__| | |  __/ | | | |_ ", 9, 9);
        printCentered("  \\_/\\_/  |_| |_|_| .__/   \\___|_|_|\\___|_| |_|\\__|", 10, 9);
        printCentered("                  |_|                              ", 11, 9);

        setColor(8);
        printCentered("                                               b0.1", 13, 8);
    }

    inline void showCountdown(int seconds) {
        std::this_thread::sleep_for(std::chrono::seconds(seconds));
    }

    inline void clearMessageArea() {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        int width = csbi.srWindow.Right - csbi.srWindow.Left + 1;

        // Clear lines 16-20
        for (int line = 16; line <= 20; line++) {
            setCursorPosition(0, line);
            for (int i = 0; i < width; i++) {
                std::cout << " ";
            }
        }
    }

    inline void showStep(const std::string& message, int current = 0, int total = 0) {
        (void)current;  // Unused
        (void)total;    // Unused

        clearMessageArea();

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        int width = csbi.srWindow.Right - csbi.srWindow.Left + 1;

        int y = 17;  // Position plus élevée
        int x = (width - static_cast<int>(message.length())) / 2;

        setCursorPosition(x, y);
        setColor(11);  // Cyan clair
        std::cout << message;
        setColor(7);
    }

    inline void showError(const std::string& message) {
        clearMessageArea();

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        int width = csbi.srWindow.Right - csbi.srWindow.Left + 1;

        int y = 17;
        int x = (width - static_cast<int>(message.length())) / 2;

        setCursorPosition(x, y);
        setColor(12);  // Rouge
        std::cout << message;
        setColor(7);
    }

    inline void showSuccess(const std::string& message) {
        clearMessageArea();

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        int width = csbi.srWindow.Right - csbi.srWindow.Left + 1;

        int y = 17;
        int x = (width - static_cast<int>(message.length())) / 2;

        setCursorPosition(x, y);
        setColor(10);  // Vert
        std::cout << message;
        setColor(7);
    }

    inline void showInfo(const std::string& message) {
        clearMessageArea();

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        int width = csbi.srWindow.Right - csbi.srWindow.Left + 1;

        int y = 17;
        int x = (width - static_cast<int>(message.length())) / 2;

        setCursorPosition(x, y);
        setColor(11);  // Cyan
        std::cout << message;
        setColor(7);
    }

    inline void showWarning(const std::string& message) {
        clearMessageArea();

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        int width = csbi.srWindow.Right - csbi.srWindow.Left + 1;

        int y = 17;
        int x = (width - static_cast<int>(message.length())) / 2;

        setCursorPosition(x, y);
        setColor(14);  // Jaune
        std::cout << message;
        setColor(7);
    }

    inline void hideWindow() {
        HWND consoleWindow = GetConsoleWindow();
        ShowWindow(consoleWindow, SW_HIDE);
    }

    inline void showWindow() {
        HWND consoleWindow = GetConsoleWindow();
        ShowWindow(consoleWindow, SW_SHOW);
        SetForegroundWindow(consoleWindow);
    }

    inline bool isProcessRunning(const wchar_t* processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return false;
    }

}