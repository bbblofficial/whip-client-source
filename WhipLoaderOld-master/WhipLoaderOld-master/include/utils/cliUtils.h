#pragma once

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>


namespace Utils {

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
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    }

    inline void clearScreen() {
        system("cls");
    }

    inline void setCursorPosition(int x, int y) {
        COORD coord;
        coord.X = x;
        coord.Y = y;
        SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coord);
    }

    inline void printCentered(const std::string& text, int y, int color) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        int width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        int x = (width - text.length()) / 2;
        setCursorPosition(x, y);
        setColor(color);
        std::cout << text;
    }

    inline void hideScrollbar() {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);

        COORD newSize;
        newSize.X = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        newSize.Y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        SetConsoleScreenBufferSize(hConsole, newSize);
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
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    inline void showStep(const std::string& message, int current, int total) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        int height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        int width = csbi.srWindow.Right - csbi.srWindow.Left + 1;

        int y = height - 5;
        int x = (width - message.length()) / 2;

        setCursorPosition(0, y);
        for (int i = 0; i < width; i++) {
            std::cout << " ";
        }

        setCursorPosition(x, y);
        setColor(15);
        std::cout << message;
        setColor(7);
    }

    inline void showError(const std::string& message) {
        setColor(12);
        std::cout << "\n[ERROR] " << message << std::endl;
        setColor(7);
    }

    inline void showSuccess(const std::string& message) {
        setColor(10);
        std::cout << "\n[SUCCESS] " << message << std::endl;
        setColor(7);
    }

    inline void hideWindow() {
        HWND consoleWindow = GetConsoleWindow();
        if (consoleWindow) {
            ShowWindow(consoleWindow, SW_HIDE);

            HWND parent = GetAncestor(consoleWindow, GA_ROOTOWNER);
            if (parent && parent != consoleWindow) {
                ShowWindow(parent, SW_HIDE);
            }
        }
    }

    inline void showWindow() {
        HWND consoleWindow = GetConsoleWindow();
        if (consoleWindow) {
            ShowWindow(consoleWindow, SW_SHOW);

            HWND parent = GetAncestor(consoleWindow, GA_ROOTOWNER);
            if (parent && parent != consoleWindow) {
                ShowWindow(parent, SW_SHOW);
                SetForegroundWindow(parent);
            }
            SetForegroundWindow(consoleWindow);
        }
    }

    inline bool isProcessRunning(const char* processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, processName) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return false;
    }

}