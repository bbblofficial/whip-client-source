# Quick Start - WhipSysCall

## 🚀 5 Minutes pour Commencer

### 1. Build la Bibliothèque

```bash
cd WhipSysCall
cmake --build cmake-build-debug --target WhipSysCall
```

**Résultat**: `cmake-build-debug/WhipSysCall.lib`

### 2. Testez l'Exemple Simple

```bash
cmake --build cmake-build-debug --target SimpleExample
cmake-build-debug\SimpleExample.exe
```

**Sortie attendue**:
```
=== WhipSysCall - Exemple Simple ===

[1] Initialisation...
    OK: 512 syscalls resolus

[2] Informations processus:
    PID: 12345
    TID: 67890
    Timestamp Unix: 1770232524

[3] Allocation memoire (8192 bytes):
    OK: Memoire allouee a 0x...
    OK: Donnees ecrites
    OK: Memoire liberee

[4] Resolution directe de NtAllocateVirtualMemory:
    SSN: 0x0018
    Adresse: 0x00007FFB...

=== Termine avec succes! ===
```

### 3. Créez Votre Premier Programme

**mon_app.cpp**:
```cpp
#include "whipsyscall/WhipSysCall.h"
#include <stdio.h>

int main() {
    // Init
    SyscallResolver resolver;
    if (!resolver.Init()) {
        printf("Erreur init!\n");
        return 1;
    }

    SyscallWrappers wrappers(&resolver);

    // Utiliser
    PVOID mem = wrappers.HeapAlloc(1024);
    printf("Memoire: 0x%p\n", mem);
    wrappers.HeapFree(mem);

    printf("PID: %lu\n", wrappers.GetCurrentProcessId());

    return 0;
}
```

**Compiler**:
```bash
# Ajouter dans CMakeLists.txt:
add_executable(MonApp mon_app.cpp)
target_link_libraries(MonApp PRIVATE WhipSysCall)

# Build:
cmake --build cmake-build-debug --target MonApp
```

## 📖 API Essentielles

### Initialisation
```cpp
SyscallResolver resolver;
resolver.Init();                    // Résout ~512 syscalls
```

### Allocation Mémoire
```cpp
SyscallWrappers wrappers(&resolver);

PVOID mem = wrappers.HeapAlloc(4096);
wrappers.HeapFree(mem);
```

### Informations Système
```cpp
DWORD pid = wrappers.GetCurrentProcessId();
DWORD tid = wrappers.GetCurrentThreadId();
QWORD time = wrappers.GetSystemTime();
```

### Appel Syscall Direct
```cpp
WORD ssn;
PVOID addr;
resolver.ResolveByName("NtDelayExecution", ssn, addr);

LARGE_INTEGER delay;
delay.QuadPart = -1000000;  // 100ms
SyscallInvoker::Invoke(ssn, FALSE, &delay);
```

## 📚 Prochaines Étapes

1. **Lire [API.md](API.md)** - Documentation complète
2. **Voir [examples/](examples/)** - Plus d'exemples
3. **Consulter [INTEGRATION.md](INTEGRATION.md)** - Intégrer dans votre projet

## ⚡ Commandes Utiles

```bash
# Build Release
cmake --build cmake-build-debug --config Release

# Clean
cmake --build cmake-build-debug --target clean

# Rebuild tout
cmake --build cmake-build-debug --clean-first

# Build un target spécifique
cmake --build cmake-build-debug --target SimpleExample
```

## 🐛 Problèmes Courants

**"Init() retourne false"**
→ Vérifiez que vous êtes sur Windows x64

**"SSN = 0x0000"**
→ Le syscall est peut-être optimisé par Windows (normal pour certaines fonctions)

**"HeapAlloc retourne nullptr"**
→ Vérifiez que Init() a réussi avant

## ✅ Checklist

- [ ] Build WhipSysCall.lib réussi
- [ ] SimpleExample fonctionne
- [ ] J'ai compris l'API de base
- [ ] J'ai lu API.md
- [ ] Prêt à intégrer dans mon projet!

---

**Prêt? Consultez [INTEGRATION.md](INTEGRATION.md) pour intégrer dans votre projet!**