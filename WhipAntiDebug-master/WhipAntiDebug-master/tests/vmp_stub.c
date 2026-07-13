// VMProtectSDK64.dll stub — all functions are NOPs
// Allows WhipAD.dll to load without the real VMProtect installed
#include <stddef.h>

#define EXPORT __declspec(dllexport)

EXPORT void __stdcall VMProtectBegin(const char* n) { (void)n; }
EXPORT void __stdcall VMProtectBeginVirtualization(const char* n) { (void)n; }
EXPORT void __stdcall VMProtectBeginMutation(const char* n) { (void)n; }
EXPORT void __stdcall VMProtectBeginUltra(const char* n) { (void)n; }
EXPORT void __stdcall VMProtectBeginVirtualizationLockByKey(const char* n) { (void)n; }
EXPORT void __stdcall VMProtectBeginUltraLockByKey(const char* n) { (void)n; }
EXPORT void __stdcall VMProtectEnd(void) { }
EXPORT int  __stdcall VMProtectIsProtected(void) { return 0; }
EXPORT int  __stdcall VMProtectIsDebuggerPresent(int k) { (void)k; return 0; }
EXPORT int  __stdcall VMProtectIsVirtualMachinePresent(void) { return 0; }
EXPORT int  __stdcall VMProtectIsValidImageCRC(void) { return 1; }
EXPORT char* __stdcall VMProtectDecryptStringA(const char* s) { return (char*)s; }
EXPORT wchar_t* __stdcall VMProtectDecryptStringW(const wchar_t* s) { return (wchar_t*)s; }
EXPORT int  __stdcall VMProtectFreeString(void* s) { (void)s; return 1; }

int __stdcall DllMain(void* h, unsigned long r, void* p) {
    (void)h; (void)r; (void)p;
    return 1;
}
