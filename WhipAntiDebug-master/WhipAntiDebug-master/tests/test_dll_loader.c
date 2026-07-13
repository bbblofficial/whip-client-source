// Loader for test_spoof_dll.dll — loads DLL, calls exports, verifies spoof
#include <stdio.h>

#pragma comment(lib, "kernel32.lib")

__declspec(dllimport) void*  __stdcall LoadLibraryA(const char*);
__declspec(dllimport) void*  __stdcall GetProcAddress(void*, const char*);
__declspec(dllimport) int    __stdcall FreeLibrary(void*);
__declspec(dllimport) void   __stdcall Sleep(unsigned long);

typedef unsigned int  u32;
typedef u32           (__cdecl *fn_u32)(void);
typedef float         (__cdecl *fn_f32)(void);
typedef const char*   (__cdecl *fn_str)(char*);
typedef const char*   (__cdecl *fn_ptr)(void);

int main(void) {
    printf("[LOADER] Loading test_spoof_dll.dll...\n");

    void* dll = LoadLibraryA("test_spoof_dll.dll");
    if (!dll) {
        printf("[LOADER] FAILED to load DLL\n");
        return 1;
    }
    printf("[LOADER] DLL loaded at %p\n", dll);

    // Wait for init thread to finish
    printf("[LOADER] Waiting for DLL init...\n"); fflush(stdout);
    Sleep(1000);

    // Get exports
    printf("[LOADER] Resolving exports...\n"); fflush(stdout);
    fn_u32 GetRealHealth    = (fn_u32)GetProcAddress(dll, "GetRealHealth");
    fn_f32 GetRealThreshold = (fn_f32)GetProcAddress(dll, "GetRealThreshold");
    fn_str GetRealString    = (fn_str)GetProcAddress(dll, "GetRealString");
    fn_ptr GetRealPointer   = (fn_ptr)GetProcAddress(dll, "GetRealPointer");

    printf("[LOADER] Health=%p Thresh=%p Str=%p Ptr=%p\n",
           (void*)GetRealHealth, (void*)GetRealThreshold,
           (void*)GetRealString, (void*)GetRealPointer);
    fflush(stdout);

    if (!GetRealHealth || !GetRealThreshold || !GetRealString || !GetRealPointer) {
        printf("[LOADER] Failed to resolve exports\n");
        FreeLibrary(dll);
        return 1;
    }

    // Call decode functions
    printf("[LOADER] Calling GetRealHealth...\n"); fflush(stdout);
    u32 health = GetRealHealth();
    printf("[LOADER] Got health=%u\n", health); fflush(stdout);
    float threshold = GetRealThreshold();
    char buf[64];
    const char* secret = GetRealString(buf);
    const char* ptr = GetRealPointer();

    printf("\n[LOADER] === SPOOF BYPASS TEST ===\n");
    printf("[LOADER] health    = %u  (should be 1, decoy was 15)\n", health);
    printf("[LOADER] threshold = %f  (should be 0.001, decoy was 3.14)\n", threshold);
    printf("[LOADER] string    = \"%s\"  (should be FLAG{dll_1nj3ct3d})\n", secret);
    printf("[LOADER] pointer   = \"%s\"  (should be REAL_SECRET_KEY)\n", ptr);

    // Verify
    int ok = 1;
    if (health != 1)       { printf("[FAIL] health != 1\n"); ok = 0; }
    if (threshold < 0.0009f || threshold > 0.0011f) { printf("[FAIL] threshold wrong\n"); ok = 0; }
    if (!secret || secret[0] != 'F') { printf("[FAIL] string wrong\n"); ok = 0; }
    if (!ptr || ptr[0] != 'R')       { printf("[FAIL] pointer wrong\n"); ok = 0; }

    if (ok) printf("\n[PASS] All spoof types work correctly in DLL context!\n");
    else    printf("\n[FAIL] Some tests failed.\n");

    printf("\n[LOADER] Done. Sleeping 120s for inspection. DLL @ %p\n", dll);
    fflush(stdout);
    Sleep(120000);

    FreeLibrary(dll);
    return ok ? 0 : 1;
}
