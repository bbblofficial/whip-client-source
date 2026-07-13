#pragma optimize("", off)
#include "whipsyscall/SyscallResolver.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

// ========== HELPERS ==========

namespace SyscallResolverHelpers {
    PVOID GetNtdllBase() {
        // VMProtectBeginUltra("SyscallResolverHelpers_GetNtdllBase");

        // PEB->Ldr->InMemoryOrderModuleList
        // ntdll est toujours le 2ème module
#ifdef _WIN64
        BYTE* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
#else
        BYTE* peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
#endif

        PVOID ldr = *reinterpret_cast<PVOID*>(peb + 0x18);
        PVOID listHead = reinterpret_cast<BYTE*>(ldr) + 0x10;
        PVOID* current = *reinterpret_cast<PVOID**>(listHead);

        // Skip premier (exe), prendre le second (ntdll)
        current = *reinterpret_cast<PVOID**>(current);

        // L'offset DllBase varie selon Windows (0x10, 0x20, ou 0x30)
        // Tester les offsets courants et vérifier la signature MZ
        const int offsets[] = { 0x30, 0x20, 0x10 };

        for (int i = 0; i < 3; i++) {
            PVOID base = *reinterpret_cast<PVOID*>(reinterpret_cast<BYTE*>(current) + offsets[i]);
            if (base) {
                // Vérifier signature MZ
                WORD magic = *reinterpret_cast<WORD*>(base);
                if (magic == 0x5A4D) {  // "MZ"
                    return base;
                    // VMProtectEnd();
                }
            }
        }

        return nullptr;
        // VMProtectEnd();
    }

    SIZE_T StrLen(const char* str) {
        // VMProtectBeginUltra("SyscallResolverHelpers_StrLen");

        SIZE_T len = 0;
        while (str[len]) len++;

        return len;
        // VMProtectEnd();
    }

    int StrCmp(const char* s1, const char* s2) {
        // VMProtectBeginUltra("SyscallResolverHelpers_StrCmp");

        while (*s1 && (*s1 == *s2)) {
            s1++;
            s2++;
        }

        return *reinterpret_cast<const BYTE*>(s1) - *reinterpret_cast<const BYTE*>(s2);
        // VMProtectEnd();
    }

    void MemCpy(void* dest, const void* src, SIZE_T n) {
        // VMProtectBeginUltra("SyscallResolverHelpers_MemCpy");

        BYTE* d = static_cast<BYTE*>(dest);
        const BYTE* s = static_cast<const BYTE*>(src);
        for (SIZE_T i = 0; i < n; i++) {
            d[i] = s[i];
        }

        // VMProtectEnd();
    }
}

// ========== SyscallResolver METHODS ==========

SyscallResolver::SyscallResolver() : count(0), ntdllBase(nullptr) {
    // VMProtectBeginUltra("SyscallResolver_SyscallResolver");

    for (int i = 0; i < MAX_SYSCALLS; i++) {
        table[i].nameHash = 0;
        table[i].ssn = 0;
        table[i].address = nullptr;
    }

    // VMProtectEnd();
}

bool SyscallResolver::InitNtdllBase() {
    // VMProtectBeginUltra("SyscallResolver_InitNtdllBase");

    ntdllBase = SyscallResolverHelpers::GetNtdllBase();

    return ntdllBase != nullptr;
    // VMProtectEnd();
}

bool SyscallResolver::ParseExportTable(PEHeaders& headers) {
    // VMProtectBeginUltra("SyscallResolver_ParseExportTable");

    if (!ntdllBase) return false;

    BYTE* base = static_cast<BYTE*>(ntdllBase);

    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dosHeader->e_magic != 0x5A4D) return false; // "MZ"

    IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dosHeader->e_lfanew);
    if (ntHeaders->Signature != 0x4550) return false; // "PE"

    IMAGE_DATA_DIRECTORY* exportDir = &ntHeaders->OptionalHeader.DataDirectory[0];
    if (exportDir->VirtualAddress == 0) return false;

    IMAGE_EXPORT_DIRECTORY* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + exportDir->VirtualAddress);

    headers.base = base;
    headers.exportNameTable = reinterpret_cast<DWORD*>(base + exports->AddressOfNames);
    headers.exportOrdinalTable = reinterpret_cast<WORD*>(base + exports->AddressOfNameOrdinals);
    headers.exportAddressTable = reinterpret_cast<DWORD*>(base + exports->AddressOfFunctions);
    headers.numberOfNames = exports->NumberOfNames;

    return true;
    // VMProtectEnd();
}

PVOID SyscallResolver::GetExportByName(const char* name) {
    // VMProtectBeginUltra("SyscallResolver_GetExportByName");

    PEHeaders headers;
    if (!ParseExportTable(headers)) return nullptr;

    for (DWORD i = 0; i < headers.numberOfNames; i++) {
        const char* exportName = reinterpret_cast<const char*>(headers.base + headers.exportNameTable[i]);

        if (SyscallResolverHelpers::StrCmp(exportName, name) == 0) {
            WORD ordinal = headers.exportOrdinalTable[i];
            DWORD rva = headers.exportAddressTable[ordinal];
            return headers.base + rva;
            // VMProtectEnd();
        }
    }

    return nullptr;
    // VMProtectEnd();
}

WORD SyscallResolver::ExtractSsnFromStub(PVOID funcAddress) {
    // VMProtectBeginUltra("SyscallResolver_ExtractSsnFromStub");

    if (!funcAddress) return 0xFFFF;

    BYTE* stub = static_cast<BYTE*>(funcAddress);

    // Follow JMP chains up to 3 levels deep.
    for (int depth = 0; depth < 3; depth++) {
        // E9 xx xx xx xx — relative near JMP
        if (stub[0] == 0xE9) {
            LONG offset = *reinterpret_cast<LONG*>(&stub[1]);
            stub = stub + 5 + offset;
            continue;
        }
        // FF 25 00 00 00 00 — JMP QWORD PTR [RIP+0]; 8-byte abs ptr follows at +6
        if (stub[0] == 0xFF && stub[1] == 0x25 &&
            stub[2] == 0x00 && stub[3] == 0x00 && stub[4] == 0x00 && stub[5] == 0x00) {
            BYTE* target = *reinterpret_cast<BYTE**>(stub + 6);
            if (!target) break;
            stub = target;
            continue;
        }
        // 90 FF 25 00 00 00 00 — NOP + JMP QWORD PTR [RIP+0] (ScyllaHide/NtHookEngine style)
        // Pointer is at +7 (NOP shifts everything by 1).
        if (stub[0] == 0x90 && stub[1] == 0xFF && stub[2] == 0x25 &&
            stub[3] == 0x00 && stub[4] == 0x00 && stub[5] == 0x00 && stub[6] == 0x00) {
            BYTE* target = *reinterpret_cast<BYTE**>(stub + 7);
            if (!target) break;
            stub = target;
            continue;
        }
        break;
    }

    // Pattern Windows 10/11 x64:
    // 4C 8B D1          mov r10, rcx
    // B8 [SSN]          mov eax, SSN (WORD)
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8) {
        return *reinterpret_cast<WORD*>(&stub[4]);
        // VMProtectEnd();
    }

    // Pattern alternatif (Win10 early):
    // B8 [SSN]          mov eax, SSN
    // 4C 8B D1          mov r10, rcx
    if (stub[0] == 0xB8) {
        return *reinterpret_cast<WORD*>(&stub[1]);
        // VMProtectEnd();
    }

    return 0xFFFF;
    // VMProtectEnd();
}

bool SyscallResolver::Init() {
    // VMProtectBeginUltra("SyscallResolver_Init");

    if (!InitNtdllBase()) return false;

    PEHeaders headers;
    if (!ParseExportTable(headers)) return false;

    count = 0;

    // Halo's Gate: collect all Nt*/Zw* entries including hooked ones (ssn==0xFFFF),
    // then gap-fill using neighbor SSNs (alphabetical order == SSN assignment order
    // on Windows 10+).
    static DWORD g_hashes[MAX_SYSCALLS];
    static PVOID g_addrs [MAX_SYSCALLS];
    static WORD  g_ssns  [MAX_SYSCALLS];
    int n = 0;

    for (DWORD i = 0; i < headers.numberOfNames && n < MAX_SYSCALLS; i++) {
        const char* name = reinterpret_cast<const char*>(headers.base + headers.exportNameTable[i]);

        // Filtrer uniquement Nt* ou Zw*
        if ((name[0] == 'N' && name[1] == 't') || (name[0] == 'Z' && name[1] == 'w')) {
            WORD  ordinal = headers.exportOrdinalTable[i];
            DWORD rva     = headers.exportAddressTable[ordinal];
            PVOID address = headers.base + rva;

            g_hashes[n] = HashFnv1a(name);
            g_addrs[n]  = address;
            g_ssns[n]   = ExtractSsnFromStub(address);
            n++;
        }
    }

    // Gap-fill: for each unresolved entry find the nearest clean neighbor and
    // interpolate (distance == SSN delta because entries are in alphabetical order).
    for (int i = 0; i < n; i++) {
        if (g_ssns[i] != 0xFFFF) continue;

        int prev = -1, next = -1;
        for (int j = i - 1; j >= 0; j--) { if (g_ssns[j] != 0xFFFF) { prev = j; break; } }
        for (int j = i + 1; j <  n; j++) { if (g_ssns[j] != 0xFFFF) { next = j; break; } }

        if (prev >= 0)
            g_ssns[i] = static_cast<WORD>(g_ssns[prev] + (i - prev));
        else if (next >= 0)
            g_ssns[i] = static_cast<WORD>(g_ssns[next] - (next - i));
        // Both -1 only if every Nt*/Zw* entry is hooked — leave as 0xFFFF.
    }

    // Populate the resolver table with all entries that now have a valid SSN.
    for (int i = 0; i < n && count < MAX_SYSCALLS; i++) {
        if (g_ssns[i] == 0xFFFF) continue;
        table[count].nameHash = g_hashes[i];
        table[count].ssn      = g_ssns[i];
        table[count].address  = g_addrs[i];
        count++;
    }

    return count > 0;
    // VMProtectEnd();
}

bool SyscallResolver::Resolve(DWORD nameHash, WORD& ssn, PVOID& address) {
    // VMProtectBeginUltra("SyscallResolver_Resolve");

    for (int i = 0; i < count; i++) {
        if (table[i].nameHash == nameHash) {
            ssn = table[i].ssn;
            address = table[i].address;
            return true;
            // VMProtectEnd();
        }
    }

    return false;
    // VMProtectEnd();
}

bool SyscallResolver::ResolveByName(const char* name, WORD& ssn, PVOID& address) {
    // VMProtectBeginUltra("SyscallResolver_ResolveByName");

    bool result = Resolve(HashFnv1a(name), ssn, address);

    return result;
    // VMProtectEnd();
}

int SyscallResolver::GetCount() const {
    // VMProtectBeginUltra("SyscallResolver_GetCount");

    return count;
    // VMProtectEnd();
}