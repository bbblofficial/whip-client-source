#include <Windows.h>
#include <ostream>

#define IMGUI_DEFINE_MATH_OPERATORS
#include "glfw/GLFW3.h"

typedef LRESULT(CALLBACK* pWindowProc) (
    _In_ HWND   hwnd,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
    );

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
