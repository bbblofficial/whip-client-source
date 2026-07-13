#ifndef WHIPSYSCALL_SYSCALLRESOLVER_H
#define WHIPSYSCALL_SYSCALLRESOLVER_H

#include "Types.h"
#include <intrin.h>

// Inclure les headers Windows minimaux pour les structures PE
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winnt.h>

// Hash FNV-1a pour noms de fonction
constexpr DWORD HashFnv1a(const char* str) {
    DWORD hash = 0x811c9dc5;
    while (*str) {
        hash ^= static_cast<BYTE>(*str++);
        hash *= 0x01000193;
    }
    return hash;
}

// Entry dans la table de résolution
struct SyscallEntry {
    DWORD nameHash;
    WORD ssn;
    PVOID address;
};

// ========== HELPERS ==========
namespace SyscallResolverHelpers {
    // Custom GetModuleHandle (évite kernel32 import)
    PVOID GetNtdllBase();

    // Custom strlen
    SIZE_T StrLen(const char* str);

    // Custom strcmp
    int StrCmp(const char* s1, const char* s2);

    // Custom memcpy
    void MemCpy(void* dest, const void* src, SIZE_T n);
}

class SyscallResolver {
private:
    static constexpr int MAX_SYSCALLS = 512;
    SyscallEntry table[MAX_SYSCALLS];
    int count;

    PVOID ntdllBase;

    // Parser PE
    struct PEHeaders {
        BYTE* base;
        DWORD* exportNameTable;
        WORD* exportOrdinalTable;
        DWORD* exportAddressTable;
        DWORD numberOfNames;
    };

    // Helpers
    bool InitNtdllBase();
    bool ParseExportTable(PEHeaders& headers);
    PVOID GetExportByName(const char* name);
    WORD ExtractSsnFromStub(PVOID funcAddress);

public:
    SyscallResolver();

    // Initialiser (parse ntdll)
    bool Init();

    // Résoudre un syscall par hash de nom
    bool Resolve(DWORD nameHash, WORD& ssn, PVOID& address);

    // Résoudre par nom (calcule le hash)
    bool ResolveByName(const char* name, WORD& ssn, PVOID& address);

    // Obtenir le nombre de syscalls résolus
    int GetCount() const;
};

#endif // WHIPSYSCALL_SYSCALLRESOLVER_H