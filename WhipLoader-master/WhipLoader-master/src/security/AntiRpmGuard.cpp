#include "security/AntiRpmGuard.h"
#include "security/Sentinel.h"

#include <Windows.h>
#include <winternl.h>   // NTSTATUS
#include <psapi.h>
#include <atomic>
#include <thread>
#include <vector>
#include <cstring>
#include <cwchar>

namespace AntiRpmGuard
{
    namespace
    {
        // SYSTEM_HANDLE_INFORMATION classes from undocumented winternl.
        constexpr ULONG SystemHandleInformation = 16;
        constexpr ULONG STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

        // Process access rights we treat as suspicious. PROCESS_VM_READ
        // means the holder can ReadProcessMemory us; PROCESS_VM_OPERATION
        // means they can VirtualAllocEx/WriteProcessMemory us; PROCESS_DUP_HANDLE
        // is a stepping stone for both.
        constexpr ULONG SUSPECT_ACCESS_MASK = PROCESS_VM_READ |
                                              PROCESS_VM_OPERATION |
                                              PROCESS_VM_WRITE;

        struct SYSTEM_HANDLE_TABLE_ENTRY
        {
            USHORT UniqueProcessId;
            USHORT CreatorBackTraceIndex;
            UCHAR  ObjectTypeIndex;
            UCHAR  HandleAttributes;
            USHORT HandleValue;
            PVOID  Object;
            ULONG  GrantedAccess;
        };

        struct SYSTEM_HANDLE_INFORMATION
        {
            ULONG NumberOfHandles;
            SYSTEM_HANDLE_TABLE_ENTRY Handles[1];
        };

        using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength);

        std::atomic<bool> g_running{false};
        std::thread g_thread;

        // Image names of processes we trust enough to skip (common system
        // services + AV that legitimately hold VM_READ handles to all
        // user processes). Lower-case basename only.
        const wchar_t* const kWhitelist[] = {
            L"explorer.exe",
            L"csrss.exe",
            L"services.exe",
            L"lsass.exe",
            L"wininit.exe",
            L"winlogon.exe",
            L"smss.exe",
            L"dwm.exe",
            L"audiodg.exe",
            L"taskhostw.exe",
            L"sihost.exe",
            L"runtimebroker.exe",
            L"systemsettings.exe",
            L"svchost.exe",
            // Common AV / EDR — they routinely scan all process memory.
            // We don't want to bump the score on Defender etc.
            L"msmpeng.exe",
            L"securityhealthservice.exe",
            L"mssense.exe",
            L"mbamservice.exe",
            L"avastsvc.exe",
            L"avgsvc.exe",
            L"bdservicehost.exe",
            L"ekrn.exe",         // ESET
            L"nortonsecurity.exe",
            L"mcshield.exe",
        };

        bool isWhitelistedImage(const wchar_t* imageName)
        {
            if (!imageName) return false;
            // Lower-case compare on basename.
            wchar_t lower[260];
            size_t i = 0;
            while (imageName[i] && i < 259)
            {
                wchar_t c = imageName[i];
                if (c >= L'A' && c <= L'Z') c += 32;
                lower[i] = c;
                i++;
            }
            lower[i] = 0;
            for (const wchar_t* w : kWhitelist)
            {
                if (std::wcscmp(lower, w) == 0) return true;
            }
            return false;
        }

        // Resolve an external process pid to its image basename.
        bool getProcessImageBasename(DWORD pid, wchar_t* out, size_t outChars)
        {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) return false;
            wchar_t fullPath[MAX_PATH] = {};
            DWORD len = MAX_PATH;
            BOOL ok = QueryFullProcessImageNameW(h, 0, fullPath, &len);
            CloseHandle(h);
            if (!ok) return false;
            // Pull the basename.
            const wchar_t* base = fullPath;
            for (DWORD k = 0; k < len; k++)
            {
                if (fullPath[k] == L'\\' || fullPath[k] == L'/') base = &fullPath[k + 1];
            }
            wcsncpy_s(out, outChars, base, _TRUNCATE);
            return true;
        }

        // For each handle whose owner != self, duplicate it locally and
        // check whether the handle's target is OUR pid. Scoped scope —
        // returns true if at least one suspect external-VM_READ handle
        // points at us.
        bool scanForRpmHandles(NtQuerySystemInformation_t fn, DWORD selfPid)
        {
            std::vector<unsigned char> buffer(64 * 1024);
            ULONG returnLength = 0;
            NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
            for (int attempt = 0; attempt < 8; attempt++)
            {
                status = fn(SystemHandleInformation, buffer.data(),
                            (ULONG)buffer.size(), &returnLength);
                if (status != static_cast<NTSTATUS>(STATUS_INFO_LENGTH_MISMATCH))
                    break;
                buffer.resize(buffer.size() * 2);
            }
            if (status < 0) return false;

            auto* info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(buffer.data());
            HANDLE selfHandle = GetCurrentProcess();
            DWORD numChecked = 0;

            for (ULONG i = 0; i < info->NumberOfHandles; i++)
            {
                const auto& e = info->Handles[i];
                if (e.UniqueProcessId == selfPid) continue;
                if ((e.GrantedAccess & SUSPECT_ACCESS_MASK) == 0) continue;

                // Cap the work — duplicating thousands of handles every
                // tick would be noticeable. Stop after a reasonable
                // sample; an attacker rarely has just ONE handle.
                if (++numChecked > 200) break;

                HANDLE owner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, e.UniqueProcessId);
                if (!owner) continue;

                HANDLE dup = nullptr;
                BOOL dupOk = DuplicateHandle(
                    owner, reinterpret_cast<HANDLE>((uintptr_t)e.HandleValue),
                    selfHandle, &dup, 0, FALSE,
                    DUPLICATE_SAME_ACCESS);
                CloseHandle(owner);
                if (!dupOk || !dup) continue;

                // Is it a process handle pointing at OUR pid?
                DWORD targetPid = GetProcessId(dup);
                CloseHandle(dup);
                if (targetPid != selfPid) continue;

                // Owner has VM_READ-class access to our pid. Whitelist
                // legit system images.
                wchar_t img[260] = {};
                if (getProcessImageBasename(e.UniqueProcessId, img, 260)
                    && isWhitelistedImage(img))
                {
                    continue;
                }
                return true;
            }
            return false;
        }

        void threadProc()
        {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (!ntdll) return;
            auto fn = reinterpret_cast<NtQuerySystemInformation_t>(
                GetProcAddress(ntdll, "NtQuerySystemInformation"));
            if (!fn) return;

            DWORD selfPid = GetCurrentProcessId();

            // Initial 5 s grace before first scan — the loader is
            // still spinning up, debugger overlays from the IDE attach
            // briefly during normal dev, etc.
            Sleep(5000);

            while (g_running.load(std::memory_order_relaxed))
            {
                if (scanForRpmHandles(fn, selfPid))
                {
                    // Bit pattern is non-zero, large enough to flip the
                    // HMAC, distinctive enough that the server-side
                    // analyzer can grep auth_tag mismatches with this
                    // signature in logs (= someone caught dumping).
                    Sentinel::reportExternalThreat(0xDEAD0001u);
                    // Don't break the loop — keep monitoring; bits are
                    // OR-accumulated.
                }
                // Jittered cadence: 12-18 s. Predictable timing helps
                // an attacker time their dump between scans.
                DWORD jitter = (GetTickCount() & 0x1FFF); // 0..8191 ms
                Sleep(12000 + jitter);
            }
        }
    }

    void start()
    {
        bool expected = false;
        if (!g_running.compare_exchange_strong(expected, true)) return;
        g_thread = std::thread(threadProc);
    }

    void stop()
    {
        if (!g_running.exchange(false)) return;
        if (g_thread.joinable()) g_thread.join();
    }
}
