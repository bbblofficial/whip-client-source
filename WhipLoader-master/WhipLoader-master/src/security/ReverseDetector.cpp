#pragma optimize("", off)
#include "security/ReverseDetector.h"
#include "security/Sentinel.h"
#include "network/WhipNexusClient.h"
#include "network/PacketOpcodes.h"

#include <Windows.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <wincodec.h>
#include <objbase.h>
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

#include <atomic>
#include <thread>
#include <cstdio>
#include <cstring>
#include <vector>

namespace ReverseDetector {
namespace {

// ─── globals ────────────────────────────────────────────────────────────────
std::atomic<bool> g_running{false};
std::thread       g_thread;
WhipNexusClient*  g_client          = nullptr;
void*             g_heartbeatThread = nullptr;
u32               g_gamePid         = 0;
char              g_serverHost[256] = {};
u16               g_serverPort      = 0;
char              g_pcName[128]     = {};
char              g_exePath[512]    = {};

inline void killGame(u32 pid) {
    if (!pid) return;
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
    if (!h) return;
    TerminateProcess(h, 0);
    CloseHandle(h);
    Sleep(50);
}

inline void strCopyN(char* dst, const char* src, u32 n) {
    if (!dst || n == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    u32 i = 0;
    while (i < n - 1 && src[i]) { dst[i] = src[i]; ++i; }
    dst[i] = '\0';
}

// ─── process self-protection ─────────────────────────────────────────────────
static void enableDebugPrivilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
}

static void hardenDacl() {
    PSID pWorldSid = nullptr;
    SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID,
                                   0,0,0,0,0,0,0, &pWorldSid))
        return;

    PSECURITY_DESCRIPTOR pSD     = nullptr;
    PACL                 pOldDACL = nullptr;
    if (GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, &pOldDACL, nullptr, &pSD) != ERROR_SUCCESS) {
        FreeSid(pWorldSid); return;
    }

    ACL_SIZE_INFORMATION aclInfo = {};
    GetAclInformation(pOldDACL, &aclInfo, sizeof(aclInfo), AclSizeInformation);

    DWORD sidLen     = GetLengthSid(pWorldSid);
    DWORD newAclSize = aclInfo.AclBytesInUse
                     + sizeof(ACCESS_DENIED_ACE) - sizeof(DWORD) + sidLen;
    PACL pNewDACL = static_cast<PACL>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newAclSize));
    if (!pNewDACL) { LocalFree(pSD); FreeSid(pWorldSid); return; }

    InitializeAcl(pNewDACL, newAclSize, ACL_REVISION);

    constexpr DWORD kDenyMask = PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME
                               | PROCESS_VM_WRITE  | PROCESS_VM_OPERATION
                               | PROCESS_CREATE_THREAD;
    AddAccessDeniedAce(pNewDACL, ACL_REVISION, kDenyMask, pWorldSid);

    for (DWORD i = 0; i < aclInfo.AceCount; ++i) {
        LPVOID pAce = nullptr;
        if (GetAce(pOldDACL, i, &pAce))
            AddAce(pNewDACL, ACL_REVISION, MAXDWORD,
                   pAce, ((ACE_HEADER*)pAce)->AceSize);
    }

    SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, pNewDACL, nullptr);

    HeapFree(GetProcessHeap(), 0, pNewDACL);
    LocalFree(pSD);
    FreeSid(pWorldSid);
}

// ─── RE-tool lists ───────────────────────────────────────────────────────────
static const wchar_t* const kToolExeNames[] = {
    L"x64dbg.exe", L"x32dbg.exe",
    L"ollydbg.exe",
    L"windbg.exe", L"windbgx.exe",
    L"ida.exe", L"ida64.exe", L"idaq.exe", L"idaq64.exe",
    L"idaw.exe", L"idaw64.exe",
    L"cheatengine-x86_64.exe", L"cheatengine-x86_64-SSE4-AVX2.exe", L"cheatengine.exe",
    L"wireshark.exe",
    L"fiddler.exe", L"fiddler4.exe", L"fiddlereverywhere.exe",
    L"charles.exe", L"mitmproxy.exe",
    L"cutter.exe", L"ghidra.exe", L"x96dbg.exe",
    L"procmon.exe", L"procmon64.exe",
    L"processhacker.exe", L"processhacker2.exe", L"systeminformer.exe",
    L"dnspy.exe", L"dnspyx.exe", L"dotpeek64.exe",
    L"frida-server.exe",
    nullptr
};

// x64dbg core DLLs — present in x64dbg's own process regardless of exe name.
static const wchar_t* const kX64dbgCoreDlls[] = {
    L"x64bridge.dll",
    L"x64gui.dll",
    L"TitanEngine.dll",
    nullptr
};

// VMP-bypass modules loaded by x64dbg as plugins (.dp64/.dll).
// ScyllaHide is the primary tool used to bypass VMP's anti-debug protections.
// These names appear in x64dbg's module list when the plugin is active.
static const wchar_t* const kVmpBypassDlls[] = {
    L"ScyllaHide.dp64",       // ScyllaHide x64dbg plugin (64-bit)
    L"ScyllaHide.dp32",       // ScyllaHide x64dbg plugin (32-bit)
    L"HideDebugger.dp64",     // older ScyllaHide release name
    L"MapScyllaHide.dp64",    // MapScyllaHide variant
    L"ScyllaHide.dll",        // ScyllaHide DLL injection mode into debuggee
    L"HideDebugger.dll",      // older injection mode name
    nullptr
};

// ─── hardware breakpoint check ───────────────────────────────────────────────
// Detects HWBPs set on any thread of our process.
// VMP-specific: reversers set DR0-DR3 at VM_BEGIN/VM_END to trace handlers.
// NOTE: ScyllaHide hooks GetThreadContext to fake zeroed DRs. This check is
// most reliable pre-attach (auth phase) before ScyllaHide's hook is active.
static bool hasHardwareBreakpoints() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    DWORD ourPid = GetCurrentProcessId();
    bool found = false;

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != ourPid) continue;

            // Skip the current thread — its DR regs reflect our own code, not a debugger.
            if (te.th32ThreadID == GetCurrentThreadId()) continue;

            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                                        FALSE, te.th32ThreadID);
            if (!hThread) continue;

            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(hThread, &ctx)) {
                // DR7 bits 0,2,4,6 = local enable for DR0-DR3 respectively.
                if ((ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) && (ctx.Dr7 & 0xFF))
                    found = true;
            }
            CloseHandle(hThread);
        } while (!found && Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return found;
}

// ─── ScyllaHide self-check ───────────────────────────────────────────────────
// Returns true if ScyllaHide (or similar) has been injected into our process.
// ScyllaHide's DLL injection mode drops a helper DLL into the debuggee to patch
// VMP anti-debug calls at the point of the call, bypassing all in-memory hooks.
static bool hasScyllaHideInSelf() {
    static const char* const kNames[] = {
        "ScyllaHide.dll",
        "HideDebugger.dll",
        "scyllahide.dll",
        "hidedebugger.dll",
        nullptr
    };
    for (int i = 0; kNames[i]; ++i) {
        if (GetModuleHandleA(kNames[i])) return true;
    }
    return false;
}

// ─── x64dbg artifact checks ─────────────────────────────────────────────────
// Enumerate \\.\pipe\* for any pipe whose name contains "x64dbg".
// x64dbg bridge (x64bridge.dll) creates a named pipe for GUI↔engine IPC;
// the exact name varies by version but always contains the "x64dbg" substring.
// This is a RUNTIME check — pipe disappears when x64dbg exits.
static bool hasX64dbgPipe() {
    WIN32_FIND_DATAW fd = {};
    HANDLE hFind = FindFirstFileW(L"\\\\.\\pipe\\*", &fd);
    if (hFind == INVALID_HANDLE_VALUE) return false;
    bool found = false;
    do {
        for (int i = 0; fd.cFileName[i] && !found; ++i) {
            wchar_t c = fd.cFileName[i];
            if ((c == L'x' || c == L'X') &&
                fd.cFileName[i+1] == L'6' &&
                fd.cFileName[i+2] == L'4' &&
                (fd.cFileName[i+3] == L'd' || fd.cFileName[i+3] == L'D') &&
                (fd.cFileName[i+4] == L'b' || fd.cFileName[i+4] == L'B') &&
                (fd.cFileName[i+5] == L'g' || fd.cFileName[i+5] == L'G'))
                found = true;
        }
    } while (!found && FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return found;
}

// Check for x64dbg debug database (.dd64) next to our own executable.
// x64dbg creates <target_path>.dd64 as soon as it opens any binary for debugging.
// File presence means THIS specific loader was opened in x64dbg at some point.
static bool hasX64dbgDatabase() {
    wchar_t path[MAX_PATH + 8] = {};
    DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (!len || len >= MAX_PATH) return false;
    static const wchar_t kSuffix[] = L".dd64";
    for (int i = 0; i < 6; ++i) path[len + i] = kSuffix[i];
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

// Check if our executable path appears in x64dbg's recent-files registry list.
// x64dbg writes HKCU\Software\x64dbg\x64dbg\Recent Files on every open.
// More targeted than checking key existence alone: confirms this exe was debugged.
static bool hasX64dbgRecentEntry() {
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\x64dbg\\x64dbg\\Recent Files",
                      0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    wchar_t ourPath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, ourPath, MAX_PATH);

    bool found = false;
    DWORD idx = 0;
    wchar_t valName[256]; DWORD nameLen;
    wchar_t valData[MAX_PATH + 4]; DWORD dataLen; DWORD type;
    while (!found) {
        nameLen = 256; dataLen = sizeof(valData); type = 0;
        if (RegEnumValueW(hKey, idx++, valName, &nameLen, nullptr, &type,
                          reinterpret_cast<BYTE*>(valData), &dataLen) != ERROR_SUCCESS)
            break;
        if (type == REG_SZ && _wcsicmp(valData, ourPath) == 0)
            found = true;
    }
    RegCloseKey(hKey);
    return found;
}

// ─── x64dbg Authenticode cert ────────────────────────────────────────────────
// Returns true if the PE at imagePath carries the x64dbg Authenticode cert
// (signer: "Duncan Ogilvie"). Catches renamed x64dbg even without DLL check.
static bool hasDuncanCert(const wchar_t* imagePath) {
    HANDLE hFile = CreateFileW(imagePath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    BYTE hdr[512]; DWORD rdn = 0;
    bool ok = ReadFile(hFile, hdr, 512, &rdn, nullptr) && rdn >= 256;
    if (!ok || hdr[0] != 'M' || hdr[1] != 'Z') { CloseHandle(hFile); return false; }

    DWORD peOff = *(DWORD*)(hdr + 0x3C);
    if (peOff + 0x98u > rdn || *(DWORD*)(hdr + peOff) != 0x00004550u) {
        CloseHandle(hFile); return false;
    }
    if (*(WORD*)(hdr + peOff + 24u) != 0x020Bu) {
        CloseHandle(hFile); return false;
    }

    DWORD sdOff  = *(DWORD*)(hdr + peOff + 24u + 0x90u);
    DWORD sdSize = *(DWORD*)(hdr + peOff + 24u + 0x94u);
    if (!sdOff || sdSize < 16u) { CloseHandle(hFile); return false; }

    SetFilePointer(hFile, static_cast<LONG>(sdOff), nullptr, FILE_BEGIN);
    BYTE cert[4096]; DWORD certRead = 0;
    DWORD toRead = sdSize < 4096u ? sdSize : 4096u;
    ReadFile(hFile, cert, toRead, &certRead, nullptr);
    CloseHandle(hFile);
    if (certRead < 14u) return false;

    static const BYTE sig[14] = {'D','u','n','c','a','n',' ','O','g','i','l','v','i','e'};
    for (DWORD i = 0u; i + 14u <= certRead; ++i) {
        if (memcmp(cert + i, sig, 14) == 0) return true;
    }
    return false;
}

// ─── process scanner (detect variant — no kill) ──────────────────────────────
// Returns true if any running process is x64dbg by name, VMP-bypass module, or cert.
// Does NOT kill — safe to use in the detection path before screenshots are ready.
static bool detectX64dbgPresent() {
    HANDLE hPSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hPSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(hPSnap, &pe)) { CloseHandle(hPSnap); return false; }

    DWORD ourPid = GetCurrentProcessId();

    do {
        if (pe.th32ProcessID == ourPid || pe.th32ProcessID == 0 || pe.th32ProcessID == 4)
            continue;

        // 1. Process name match (catches x64dbg.exe running under its real name)
        for (int i = 0; kToolExeNames[i]; ++i) {
            if (_wcsicmp(pe.szExeFile, kToolExeNames[i]) == 0) {
                CloseHandle(hPSnap);
                return true;
            }
        }

        // 2. Module scan — x64bridge.dll / ScyllaHide.dp64 (catches renamed x64dbg)
        HANDLE hMSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                  pe.th32ProcessID);
        if (hMSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me = {};
            me.dwSize = sizeof(me);
            if (Module32FirstW(hMSnap, &me)) {
                do {
                    for (int i = 0; kX64dbgCoreDlls[i]; ++i) {
                        if (_wcsicmp(me.szModule, kX64dbgCoreDlls[i]) == 0) {
                            CloseHandle(hMSnap);
                            CloseHandle(hPSnap);
                            return true;
                        }
                    }
                    for (int i = 0; kVmpBypassDlls[i]; ++i) {
                        if (_wcsicmp(me.szModule, kVmpBypassDlls[i]) == 0) {
                            CloseHandle(hMSnap);
                            CloseHandle(hPSnap);
                            return true;
                        }
                    }
                } while (Module32NextW(hMSnap, &me));
            }
            CloseHandle(hMSnap);
        }

        // 3. Authenticode cert (catches renamed x64dbg with cert still intact)
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (hProc) {
            wchar_t imgPath[1024]; DWORD pathLen = 1023;
            if (QueryFullProcessImageNameW(hProc, 0, imgPath, &pathLen) && pathLen > 5) {
                if (hasDuncanCert(imgPath)) {
                    CloseHandle(hProc);
                    CloseHandle(hPSnap);
                    return true;
                }
            }
            CloseHandle(hProc);
        }
    } while (Process32NextW(hPSnap, &pe));

    CloseHandle(hPSnap);
    return false;
}

// ─── RE-tool killer (existing kill functions) ─────────────────────────────────
static void killTools() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(hSnap, &pe)) { CloseHandle(hSnap); return; }

    do {
        for (int i = 0; kToolExeNames[i]; ++i) {
            if (_wcsicmp(pe.szExeFile, kToolExeNames[i]) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); }
                break;
            }
        }
    } while (Process32NextW(hSnap, &pe));

    CloseHandle(hSnap);
}

// Kill processes that carry x64dbg/ScyllaHide modules — catches renamed x64dbg
// and processes with VMP-bypass tooling loaded.
static void killByModule() {
    HANDLE hPSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hPSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(hPSnap, &pe)) { CloseHandle(hPSnap); return; }

    DWORD ourPid = GetCurrentProcessId();
    do {
        if (pe.th32ProcessID == ourPid || pe.th32ProcessID == 0 || pe.th32ProcessID == 4)
            continue;

        HANDLE hMSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                  pe.th32ProcessID);
        if (hMSnap == INVALID_HANDLE_VALUE) continue;

        MODULEENTRY32W me = {};
        me.dwSize = sizeof(me);
        bool found = false;
        if (Module32FirstW(hMSnap, &me)) {
            do {
                // Core x64dbg DLLs
                for (int i = 0; !found && kX64dbgCoreDlls[i]; ++i)
                    if (_wcsicmp(me.szModule, kX64dbgCoreDlls[i]) == 0)
                        found = true;
                // VMP-bypass DLLs (ScyllaHide plugins and injection DLLs)
                for (int i = 0; !found && kVmpBypassDlls[i]; ++i)
                    if (_wcsicmp(me.szModule, kVmpBypassDlls[i]) == 0)
                        found = true;
            } while (!found && Module32NextW(hMSnap, &me));
        }
        CloseHandle(hMSnap);

        if (found) {
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); }
        }
    } while (Process32NextW(hPSnap, &pe));

    CloseHandle(hPSnap);
}

// Kill processes whose Authenticode cert identifies them as x64dbg (Duncan Ogilvie).
static void killByCert() {
    HANDLE hPSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hPSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(hPSnap, &pe)) { CloseHandle(hPSnap); return; }

    DWORD ourPid = GetCurrentProcessId();
    do {
        if (pe.th32ProcessID == ourPid || pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (!hProc) continue;
        wchar_t imgPath[1024]; DWORD pathLen = 1023;
        bool gotPath = QueryFullProcessImageNameW(hProc, 0, imgPath, &pathLen) && pathLen > 5;
        CloseHandle(hProc);
        if (!gotPath) continue;

        if (hasDuncanCert(imgPath)) {
            HANDLE hKill = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (hKill) { TerminateProcess(hKill, 0); CloseHandle(hKill); }
        }
    } while (Process32NextW(hPSnap, &pe));

    CloseHandle(hPSnap);
}

// ─── per-monitor WIC JPEG capture ───────────────────────────────────────────
static std::vector<uint8_t> captureRectJpeg(int mx, int my, int mw, int mh) {
    std::vector<uint8_t> result;
    if (mw <= 0 || mh <= 0) return result;

    int dw = mw / 2;
    int dh = mh / 2;

    HDC     hdcScreen = GetDC(nullptr);
    if (!hdcScreen) return result;
    HDC     hdcMem    = CreateCompatibleDC(hdcScreen);
    HBITMAP hbm       = CreateCompatibleBitmap(hdcScreen, dw, dh);
    HGDIOBJ hOld      = SelectObject(hdcMem, hbm);
    SetStretchBltMode(hdcMem, HALFTONE);
    StretchBlt(hdcMem, 0, 0, dw, dh, hdcScreen, mx, my, mw, mh, SRCCOPY);
    SelectObject(hdcMem, hOld);
    DeleteDC(hdcMem);
    ReleaseDC(nullptr, hdcScreen);

    BITMAPINFOHEADER bi = {};
    bi.biSize        = sizeof(bi);
    bi.biWidth       = dw;
    bi.biHeight      = -dh;
    bi.biPlanes      = 1;
    bi.biBitCount    = 24;
    bi.biCompression = BI_RGB;
    UINT stride = (static_cast<UINT>(dw) * 3u + 3u) & ~3u;

    std::vector<uint8_t> pixels(static_cast<size_t>(stride) * dh);
    HDC hdcTmp = CreateCompatibleDC(nullptr);
    GetDIBits(hdcTmp, hbm, 0, static_cast<UINT>(dh),
              pixels.data(), reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS);
    DeleteDC(hdcTmp);
    DeleteObject(hbm);

    do {
        IWICImagingFactory* pFact = nullptr;
        HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr,
                                      CLSCTX_INPROC_SERVER, IID_IWICImagingFactory,
                                      reinterpret_cast<void**>(&pFact));
        if (FAILED(hr) || !pFact) break;

        IStream* pStream = nullptr;
        hr = CreateStreamOnHGlobal(nullptr, TRUE, &pStream);
        if (FAILED(hr) || !pStream) { pFact->Release(); break; }

        IWICBitmapEncoder* pEnc = nullptr;
        hr = pFact->CreateEncoder(GUID_ContainerFormatJpeg, nullptr, &pEnc);
        if (FAILED(hr) || !pEnc) { pStream->Release(); pFact->Release(); break; }

        hr = pEnc->Initialize(pStream, WICBitmapEncoderNoCache);
        if (FAILED(hr)) { pEnc->Release(); pStream->Release(); pFact->Release(); break; }

        IWICBitmapFrameEncode* pFrame = nullptr;
        IPropertyBag2*         pProps = nullptr;
        hr = pEnc->CreateNewFrame(&pFrame, &pProps);
        if (FAILED(hr) || !pFrame) { pEnc->Release(); pStream->Release(); pFact->Release(); break; }
        if (pProps) { pProps->Release(); pProps = nullptr; }

        hr = pFrame->Initialize(nullptr);
        if (SUCCEEDED(hr)) hr = pFrame->SetSize(static_cast<UINT>(dw), static_cast<UINT>(dh));
        if (FAILED(hr)) { pFrame->Release(); pEnc->Release(); pStream->Release(); pFact->Release(); break; }

        WICPixelFormatGUID fmt = GUID_WICPixelFormat24bppBGR;
        hr = pFrame->SetPixelFormat(&fmt);
        if (FAILED(hr)) { pFrame->Release(); pEnc->Release(); pStream->Release(); pFact->Release(); break; }

        hr = pFrame->WritePixels(static_cast<UINT>(dh), stride,
                                 static_cast<UINT>(pixels.size()), pixels.data());
        if (SUCCEEDED(hr)) hr = pFrame->Commit();
        if (SUCCEEDED(hr)) hr = pEnc->Commit();
        if (FAILED(hr)) { pFrame->Release(); pEnc->Release(); pStream->Release(); pFact->Release(); break; }

        HGLOBAL hg = nullptr;
        if (SUCCEEDED(GetHGlobalFromStream(pStream, &hg))) {
            SIZE_T sz = GlobalSize(hg);
            void*   p = GlobalLock(hg);
            if (p && sz > 0)
                result.assign(static_cast<uint8_t*>(p),
                              static_cast<uint8_t*>(p) + sz);
            GlobalUnlock(hg);
        }

        pFrame->Release();
        pEnc->Release();
        pStream->Release();
        pFact->Release();
    } while (false);

    return result;
}

struct MonitorRect { int x, y, w, h; };

static BOOL CALLBACK enumMonitorProc(HMONITOR, HDC, LPRECT lprc, LPARAM lp) {
    auto* v = reinterpret_cast<std::vector<MonitorRect>*>(lp);
    v->push_back({ lprc->left, lprc->top,
                   (int)(lprc->right  - lprc->left),
                   (int)(lprc->bottom - lprc->top) });
    return TRUE;
}

static std::vector<std::vector<uint8_t>> captureAllScreensCore() {
    std::vector<std::vector<uint8_t>> result;

    std::vector<MonitorRect> monitors;
    EnumDisplayMonitors(nullptr, nullptr, enumMonitorProc,
                        reinterpret_cast<LPARAM>(&monitors));

    if (monitors.empty()) {
        int sx = GetSystemMetrics(SM_XVIRTUALSCREEN);
        int sy = GetSystemMetrics(SM_YVIRTUALSCREEN);
        int sw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        int sh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        auto shot = captureRectJpeg(sx, sy, sw, sh);
        if (!shot.empty()) result.push_back(std::move(shot));
        return result;
    }

    for (auto& m : monitors) {
        auto shot = captureRectJpeg(m.x, m.y, m.w, m.h);
        if (!shot.empty()) result.push_back(std::move(shot));
    }
    return result;
}

// ─── background thread ──────────────────────────────────────────────────────
void threadProc() {
    for (int i = 0; i < 10 && g_running.load(std::memory_order_relaxed); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto rdLog = [](const char*) {};

    HRESULT hrCom   = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool comOwned   = (hrCom == S_OK || hrCom == S_FALSE);
    bool comReady   = (hrCom == S_OK || hrCom == S_FALSE || hrCom == RPC_E_CHANGED_MODE);

    std::vector<std::vector<uint8_t>> lastShots;

    while (g_running.load(std::memory_order_relaxed)) {
        if (comReady) lastShots = captureAllScreensCore();

        Sentinel::recheck();
        unsigned scoreVal = Sentinel::score();
        bool     redetVal = Sentinel::reDetect();

        // VMP-specific: hardware BPs on our threads indicate a reverser is
        // tracing VMP handlers. ScyllaHide injected means bypass is active.
        bool x64dbgVal = hasHardwareBreakpoints()
                      || hasScyllaHideInSelf()
                      || detectX64dbgPresent();

#ifdef WHIP_BYPASS_MODE
        // reDetect() est un faux positif persistant dans Electron/Node.js (Lunar Client).
        // On l'exclut de la condition de kill et du toolMask envoyé au serveur.
        bool shouldKill = (scoreVal >= 50u || x64dbgVal);
        bool useRedet = false;
#else
        bool shouldKill = (scoreVal >= 50u || redetVal || x64dbgVal);
        bool useRedet = redetVal;
#endif
        if (shouldKill) {
            CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
                Sleep(3000);
                TerminateProcess(GetCurrentProcess(), 0);
                return 0;
            }, nullptr, 0, nullptr);

            killTools();
            killByModule();
            killByCert();

            bool sent = false;
            if (g_client && g_client->isConnected()) {
                u32 toolMask = useRedet ? Sentinel::reDetectMask() : 0u;
                std::string report = Sentinel::layerReport();
                g_client->sendReverseDetected(toolMask, scoreVal,
                    Sentinel::checksRun(), Sentinel::checksHit(),
                    Sentinel::hitFlags(),
                    report.c_str(), g_pcName, g_exePath, &lastShots);
                sent = true;
            }

            (void)sent;
            killGame(g_gamePid);
            std::this_thread::sleep_for(std::chrono::milliseconds(800));
            TerminateProcess(GetCurrentProcess(), 0);
        }

        // 500ms poll — two chunks of 250ms so the stop flag is checked mid-sleep.
        DWORD stepped = 0;
        while (stepped < 500u && g_running.load(std::memory_order_relaxed)) {
            DWORD chunk = (500u - stepped < 100u) ? (500u - stepped) : 100u;
            std::this_thread::sleep_for(std::chrono::milliseconds(chunk));
            stepped += chunk;
        }
    }

    if (comOwned) CoUninitialize();
}

} // anonymous namespace

// ─── public API ─────────────────────────────────────────────────────────────

void killDebugTools() {
    killTools();
    killByModule();
    killByCert();
}

// Passive detection: returns true if x64dbg or VMP-bypass tooling is found
// without killing anything. Ordered from fastest to slowest:
//   • hardware BPs on our threads (VMP tracing artifact)
//   • ScyllaHide DLL injected into our process (VMP bypass DLL injection mode)
//   • named pipe with "x64dbg" in name (runtime IPC pipe, any version)
//   • .dd64 database file next to our exe (created on open, persists)
//   • our exe path in x64dbg recent-files registry (persists across sessions)
//   • process/module/cert scan for x64dbg (renamed or standard)
bool isX64dbgDetected() {
    return hasHardwareBreakpoints()
        || hasScyllaHideInSelf()
        || hasX64dbgPipe()
        || hasX64dbgDatabase()
        || hasX64dbgRecentEntry()
        || detectX64dbgPresent();
}

void protect() {
    enableDebugPrivilege();
    hardenDacl();
}

std::vector<std::vector<uint8_t>> captureScreen() {
    HRESULT hr    = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool comOwned = (hr == S_OK || hr == S_FALSE);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return {};
    auto result = captureAllScreensCore();
    if (comOwned) CoUninitialize();
    return result;
}

void start(WhipNexusClient* client, void* heartbeatThread,
           const char* pcName, const char* executablePath, uint32_t gamePid) {
    protect();

    if (client) {
        g_client          = client;
        g_heartbeatThread = heartbeatThread;
        client->getServerAddress(g_serverHost, sizeof(g_serverHost), &g_serverPort);
    }
    if (gamePid) g_gamePid = gamePid;
    if (pcName)         strCopyN(g_pcName,  pcName,         sizeof(g_pcName));
    if (executablePath) strCopyN(g_exePath, executablePath, sizeof(g_exePath));
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) return;
    g_thread = std::thread(threadProc);
}

void stop() {
    if (!g_running.exchange(false)) return;
    if (g_thread.joinable()) g_thread.join();
}

void checkAndKill(WhipNexusClient* client, const char* tag, uint32_t gamePid) {
    (void)tag;
    u32 pid = gamePid ? gamePid : g_gamePid;
    Sentinel::recheck();
    unsigned s   = Sentinel::score();
    bool     rd  = Sentinel::reDetect();
    bool     x64 = isX64dbgDetected();

#ifdef WHIP_BYPASS_MODE
    // reDetect() = faux positif dans Electron — exclu du kill et du toolMask.
    if (s < 50u && !x64) return;
    bool useRd = false;
#else
    if (s < 50u && !rd && !x64) return;
    bool useRd = rd;
#endif

    auto shots = captureScreen();
    killTools();
    killByModule();
    killByCert();

    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        Sleep(3000);
        TerminateProcess(GetCurrentProcess(), 0);
        return 0;
    }, nullptr, 0, nullptr);

    if (client) {
        u32 toolMask = useRd ? Sentinel::reDetectMask() : 0u;
        std::string report = Sentinel::layerReport();
        client->sendReverseDetected(toolMask, s,
            Sentinel::checksRun(), Sentinel::checksHit(),
            Sentinel::hitFlags(),
            report.c_str(), g_pcName, g_exePath, &shots);
    }
    killGame(pid);
    Sleep(800);
    TerminateProcess(GetCurrentProcess(), 0);
}

} // namespace ReverseDetector
#pragma optimize("", on)
