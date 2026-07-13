# WhipSysCall

> Bibliothèque C++ pour invocation directe de syscalls Windows x64 sans passer par ntdll.dll

[![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue)]()
[![C++](https://img.shields.io/badge/C++-20-00599C)]()
[![License](https://img.shields.io/badge/license-Educational-green)]()

## ✨ Fonctionnalités

- ✅ **Résolution dynamique des SSN** - Parse ntdll.dll en mémoire, extrait ~512 syscalls
- ✅ **Invocation directe** - Shellcode x64 pour appeler n'importe quel syscall (jusqu'à 10 arguments)
- ✅ **API haut niveau** - Wrappers pour HeapAlloc, VirtualAlloc, GetSystemTime, etc.
- ✅ **Zero imports suspects** - Pas de GetProcAddress, LoadLibrary
- ✅ **Bypass hooks userland** - Évite les hooks IAT/EAT/Inline de ntdll

## 🚀 Démarrage Rapide

### Installation

```bash
git clone https://github.com/votre-repo/WhipSysCall
cd WhipSysCall
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
```

### Exemple Basique

```cpp
#include "whipsyscall/WhipSysCall.h"
#include <stdio.h>

int main() {
    // 1. Initialiser
    SyscallResolver resolver;
    resolver.Init();  // Résout ~512 syscalls

    SyscallWrappers wrappers(&resolver);

    // 2. Allouer mémoire (bypass malloc)
    PVOID mem = wrappers.HeapAlloc(4096);
    if (mem) {
        memset(mem, 0x41, 4096);
        wrappers.HeapFree(mem);
    }

    // 3. Infos système
    printf("PID: %lu\n", wrappers.GetCurrentProcessId());
    printf("Timestamp: %llu\n", wrappers.GetSystemTime());

    return 0;
}
```

**Sortie**:
```
PID: 12345
Timestamp: 1770232524
```

## 📖 Documentation

- **[API Reference](API.md)** - Documentation complète de l'API
- **[Guide Technique](EXPLICATION_TECHNIQUE.md)** - Détails d'implémentation
- **[Exemples](examples/)** - Exemples d'utilisation

## 🎯 Cas d'Usage

### ✅ Légitimes
- 🔍 Recherche en sécurité
- 🛡️ Développement d'outils de défense
- 🏆 CTF / Wargames
- 🐛 Debugging bas niveau
- 📚 Éducation / Reverse engineering

### ❌ Interdits
- ❌ Malware
- ❌ Rootkits
- ❌ Évasion de sécurité malveillante

## 🏗️ Architecture

```
WhipSysCall/
├── include/whipsyscall/
│   ├── Types.h              # Types Windows (BYTE, DWORD, etc.)
│   ├── SyscallResolver.h    # Résolution SSN
│   ├── SyscallInvoker.h     # Invocation syscall
│   ├── SyscallWrappers.h    # API haut niveau
│   └── WhipSysCall.h        # Header principal
├── src/
│   ├── SyscallResolver.cpp  # Parser PE ntdll
│   ├── SyscallInvoker.cpp   # Wrapper C++
│   ├── SyscallStub.asm      # Shellcode x64 MASM
│   └── SyscallWrappers.cpp  # Implémentation wrappers
└── examples/
    ├── simple.cpp           # Exemple simple
    └── example.cpp          # Exemple complet
```

## 🔧 API Principale

### SyscallResolver

```cpp
SyscallResolver resolver;
resolver.Init();                        // Résout les syscalls

WORD ssn;
PVOID addr;
resolver.ResolveByName("NtAllocateVirtualMemory", ssn, addr);
printf("SSN: 0x%04X\n", ssn);           // Ex: 0x0018
```

### SyscallInvoker

```cpp
// Appel direct avec SSN
NTSTATUS status = SyscallInvoker::Invoke(
    0x0018,              // SSN
    arg1, arg2, ...      // Arguments (max 10)
);
```

### SyscallWrappers

```cpp
SyscallWrappers wrappers(&resolver);

// Mémoire
PVOID mem = wrappers.HeapAlloc(1024);
wrappers.HeapFree(mem);

PVOID exec = wrappers.VirtualAlloc(4096, PAGE_EXECUTE_READWRITE);
wrappers.VirtualFree(exec, 4096);

// Système
DWORD pid = wrappers.GetCurrentProcessId();
DWORD tid = wrappers.GetCurrentThreadId();
QWORD time = wrappers.GetSystemTime();  // Unix timestamp
```

## 🔬 Détails Techniques

### Pattern Matching SSN
Détecte les patterns d'opcodes dans ntdll:
```asm
4C 8B D1              ; mov r10, rcx
B8 [XX XX] 00 00      ; mov eax, SSN  ← Extrait ici!
0F 05                 ; syscall
C3                    ; ret
```

### Shellcode Syscall
```asm
SyscallStub:
    mov eax, ecx          ; SSN → EAX
    mov rcx, rdx          ; Décaler arguments
    mov rdx, r8
    mov r8, r9
    mov r9, [rsp+28h]
    mov r10, rcx          ; R10 = RCX (convention syscall)
    syscall               ; Appel direct!
    ret
```

### Évite les Hooks
```
Normal:  App → kernel32 → ntdll → [HOOK EDR] → syscall
WhipSysCall: App → syscall direct (bypass hooks!)
```

## ✅ Tests et Validation

```bash
# Build et test
cmake --build build --config Release
build\Release\SimpleExample.exe
```

**Résultats attendus**:
- ✅ 512 syscalls résolus
- ✅ Allocation mémoire fonctionne
- ✅ PID/TID/Timestamp valides

## 📊 Compatibilité

| OS | Architecture | Statut |
|----|--------------|--------|
| Windows 10 | x64 | ✅ Testé |
| Windows 11 | x64 | ✅ Testé |
| Windows 7/8 | x64 | ⚠️ Non testé |
| Windows | x86 | ❌ Non supporté |

## 🤝 Contribution

Les contributions sont bienvenues pour:
- 🐛 Corrections de bugs
- 📝 Amélioration documentation
- ✨ Nouveaux wrappers
- 🧪 Tests supplémentaires

## ⚠️ Avertissement

Cette bibliothèque est destinée à un **usage éducatif et de recherche légitime**. L'utilisation pour des activités malveillantes est strictement interdite.

## 📝 Licence

Usage éducatif / Recherche uniquement.

## 📚 Ressources

- [Windows NT Syscall Table](https://j00ru.vexillium.org/syscalls/nt/64/)
- [MSDN - Nt Functions](https://docs.microsoft.com/en-us/windows/win32/api/)
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

---

**Made for educational and security research purposes**