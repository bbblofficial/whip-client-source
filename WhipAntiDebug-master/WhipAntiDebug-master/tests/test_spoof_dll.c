// test_spoof_dll.c — Manual-map compatible DLL for testing int_spoof
//
// ZERO IMPORTS: no IAT, no CRT, no LoadLibrary/GetProcAddress.
// Everything resolved via PEB walk (api_hash.h) or direct syscall.
// Works with: manual mapping, LoadLibrary injection, reflective loading.
//
#include <intrin.h>
#include "../antidebug/core/int_spoof.h"

// Suppress CRT float init — we handle floats manually via bit-cast
int _fltused = 0;
#include "../antidebug/core/api_hash.h"
#include "../antidebug/core/string_encrypt.h"

// ---------------------------------------------------------------------------
// Spoofed globals — visible in memory dump
// ---------------------------------------------------------------------------
static volatile ad_spoof_u32   g_health;
static volatile ad_spoof_f32   g_threshold;
static volatile ad_spoof_str   g_secret;
static volatile ad_spoof_ptr   g_ptr;
static volatile b32            g_ready = 0;

static const char g_real_data[] = "REAL_SECRET_KEY";
static const char g_fake_data[] = "placeholder_value";

// ---------------------------------------------------------------------------
// NtCreateThreadEx via direct syscall — zero imports
// ---------------------------------------------------------------------------

// SSN resolver: walk ntdll exports manually to find syscall number
// This avoids needing whip_bridge_init() which requires the C++ bridge
ANTIDEBUG_INLINE u16 ad_manual_resolve_ssn(const char* func_name) {
    // Find ntdll base via PEB
    u8* peb = (u8*)__readgsqword(0x60);
    u8* ldr = *(u8**)(peb + 0x18);
    u8* list_head = ldr + 0x10;    // InLoadOrderModuleList
    u8* entry = *(u8**)list_head;

    void* ntdll_base = 0;
    // ntdll is typically the 2nd module in load order (after exe)
    // Walk until we find it
    u32 idx = 0;
    while (entry != list_head && idx < 10) {
        void* base = *(void**)(entry + 0x30);  // DllBase
        u16*  name = *(u16**)(entry + 0x60);   // BaseDllName.Buffer
        u16   nlen = *(u16*)(entry + 0x58);    // BaseDllName.Length (bytes)

        // Check if name contains "ntdll"
        if (nlen >= 10 && name) {  // "ntdll" = 5 chars = 10 bytes
            if ((name[0] == 'n' || name[0] == 'N') &&
                (name[1] == 't' || name[1] == 'T') &&
                (name[2] == 'd' || name[2] == 'D') &&
                (name[3] == 'l' || name[3] == 'L') &&
                (name[4] == 'l' || name[4] == 'L')) {
                ntdll_base = base;
                break;
            }
        }
        entry = *(u8**)entry;
        idx++;
    }

    if (!ntdll_base) return 0xFFFF;

    // Parse ntdll exports
    u8* base = (u8*)ntdll_base;
    u32 e_lfanew = *(u32*)(base + 0x3C);
    u8* pe = base + e_lfanew;
    // Export directory RVA is at optional header offset 112 (PE32+)
    u32 export_rva = *(u32*)(pe + 24 + 112);
    if (!export_rva) return 0xFFFF;

    u8* exports = base + export_rva;
    u32 num_names = *(u32*)(exports + 0x18);
    u32* names    = (u32*)(base + *(u32*)(exports + 0x20));
    u16* ordinals = (u16*)(base + *(u32*)(exports + 0x24));
    u32* funcs    = (u32*)(base + *(u32*)(exports + 0x1C));

    for (u32 i = 0; i < num_names; i++) {
        const char* name = (const char*)(base + names[i]);
        // Compare names
        const char* a = func_name;
        const char* b = name;
        b32 match = 1;
        while (*a && *b) {
            if (*a != *b) { match = 0; break; }
            a++; b++;
        }
        if (match && *a == 0 && *b == 0) {
            // Found — read SSN from function prologue
            // Nt* functions start with: mov r10, rcx; mov eax, <SSN>
            // Bytes: 4C 8B D1 B8 XX XX 00 00
            u8* func = base + funcs[ordinals[i]];
            if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 &&
                func[3] == 0xB8) {
                return *(u16*)(func + 4);
            }
            return 0xFFFF;
        }
    }
    return 0xFFFF;
}

// Minimal syscall stub via inline asm (MSVC x64 doesn't support inline asm)
// We use the ntdll gadget approach: find "syscall; ret" in ntdll
ANTIDEBUG_INLINE void* ad_find_syscall_gadget(void) {
    u8* peb = (u8*)__readgsqword(0x60);
    u8* ldr = *(u8**)(peb + 0x18);
    u8* list_head = ldr + 0x10;
    u8* entry = *(u8**)list_head;

    while (entry != list_head) {
        void* base = *(void**)(entry + 0x30);
        u16*  name = *(u16**)(entry + 0x60);
        u16   nlen = *(u16*)(entry + 0x58);

        if (nlen >= 10 && name &&
            (name[0] == 'n' || name[0] == 'N') &&
            (name[1] == 't' || name[1] == 'T')) {
            // Found ntdll — scan for syscall;ret (0F 05 C3)
            u8* scan = (u8*)base;
            u32 pe_off = *(u32*)(scan + 0x3C);
            u32 text_size = *(u32*)(scan + pe_off + 24 + 8); // SizeOfCode
            for (u32 j = 0; j < text_size - 3; j++) {
                if (scan[j] == 0x0F && scan[j+1] == 0x05 && scan[j+2] == 0xC3) {
                    return scan + j;
                }
            }
        }
        entry = *(u8**)entry;
    }
    return 0;
}

// Call syscall via ntdll gadget — works without any imports
// NtCreateThreadEx has 11 params, we use the standard approach:
// mov r10, rcx; mov eax, SSN; jmp [syscall_gadget]
// But MSVC x64 doesn't have inline asm, so we call ntdll's own Nt* functions
// after resolving them via PEB walk. This IS manual-map safe because we
// resolve from ntdll which is always loaded.

typedef long (__stdcall *fn_NtCreateThreadEx)(
    void** handle, unsigned long access, void* oa, void* process,
    void* start, void* param, unsigned long flags,
    unsigned long long zero_bits, unsigned long long stack_size,
    unsigned long long max_stack, void* attr_list);

typedef long (__stdcall *fn_NtSetInfoThread)(
    void* handle, unsigned long info_class, void* info, unsigned long len);

typedef long (__stdcall *fn_NtResumeThread)(
    void* handle, unsigned long* suspend_count);

typedef long (__stdcall *fn_NtDelayExecution)(
    unsigned char alertable, long long* interval);

// Resolve ntdll function by hash — manual map safe
ANTIDEBUG_INLINE void* ad_ntdll_func(u32 func_hash) {
    return ad_resolve_api(AD_HASH_NTDLL, func_hash);
}

// ---------------------------------------------------------------------------
// Init thread — initializes all spoofed values
// ---------------------------------------------------------------------------
static unsigned long __stdcall spoof_init_thread(void* param) {
    (void)param;

    // Initialize all spoof types
    ad_spoof32_init((ad_spoof_u32*)&g_health, 1, 15);
    ad_spoof_f32_init((ad_spoof_f32*)&g_threshold, 0.001f, 3.14f);
    ad_spoof_str_init((ad_spoof_str*)&g_secret, "FLAG{dll_m4nual_m4p}", "Access Denied");
    ad_spoof_ptr_init((ad_spoof_ptr*)&g_ptr, g_real_data, g_fake_data);

    AD_BARRIER();
    g_ready = 1;

    return 0;
}

// ---------------------------------------------------------------------------
// DllMain — works with manual mapping (zero imports)
// ---------------------------------------------------------------------------
#if defined(_MSC_VER)
__declspec(dllexport)
#endif
int __stdcall DllMain(void* hinstDLL, u32 fdwReason, void* lpvReserved) {
    (void)hinstDLL; (void)lpvReserved;

    if (fdwReason == 1) {  // DLL_PROCESS_ATTACH
        // Resolve NtCreateThreadEx from ntdll via PEB walk — no imports needed
        fn_NtCreateThreadEx pCreate = (fn_NtCreateThreadEx)
            ad_ntdll_func(AD_HASH("NtCreateThreadEx"));

        fn_NtSetInfoThread pSetInfo = (fn_NtSetInfoThread)
            ad_ntdll_func(AD_HASH("NtSetInformationThread"));

        fn_NtResumeThread pResume = (fn_NtResumeThread)
            ad_ntdll_func(AD_HASH("NtResumeThread"));

        if (pCreate) {
            void* thread_handle = 0;
            long status = pCreate(
                &thread_handle,
                0x1FFFFF,           // THREAD_ALL_ACCESS
                0,                  // ObjectAttributes
                (void*)(long long)(-1),  // NtCurrentProcess
                (void*)&spoof_init_thread,
                0,                  // Parameter
                0x00000004,         // CREATE_SUSPENDED
                0, 0, 0,            // ZeroBits, StackSize, MaxStack
                0                   // AttributeList
            );

            if (status >= 0 && thread_handle) {
                // Hide thread from debugger
                if (pSetInfo) {
                    pSetInfo(thread_handle, 17, 0, 0);  // ThreadHideFromDebugger
                }
                // Resume
                if (pResume) {
                    pResume(thread_handle, 0);
                }
                // Don't close handle — keeps thread alive
            }
        } else {
            // Fallback: init in-place (risky under loader lock, but works for manual map
            // since manual mappers typically don't hold the loader lock)
            spoof_init_thread(0);
        }
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Exports — callable by injector after init
// ---------------------------------------------------------------------------
__declspec(dllexport) u32 GetRealHealth(void) {
    if (!g_ready) return 0xDEADu;
    return ad_spoof32_load((ad_spoof_u32*)&g_health);
}

__declspec(dllexport) float GetRealThreshold(void) {
    if (!g_ready) return -1.0f;
    return ad_spoof_f32_load((ad_spoof_f32*)&g_threshold);
}

__declspec(dllexport) const char* GetRealString(char* buf) {
    if (!g_ready) return 0;
    return ad_spoof_str_load((ad_spoof_str*)&g_secret, buf);
}

__declspec(dllexport) const char* GetRealPointer(void) {
    if (!g_ready) return 0;
    return (const char*)ad_spoof_ptr_load((ad_spoof_ptr*)&g_ptr);
}

__declspec(dllexport) b32 IsReady(void) {
    return g_ready;
}
