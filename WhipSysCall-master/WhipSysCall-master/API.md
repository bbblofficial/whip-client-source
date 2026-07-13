# WhipSysCall - Documentation API

## Vue d'ensemble

WhipSysCall est une bibliothèque C++ permettant d'invoquer directement les syscalls Windows x64 sans passer par ntdll.dll.

## Composants Principaux

### 1. SyscallResolver

**Responsabilité**: Résoudre les System Service Numbers (SSN) depuis ntdll.dll.

#### Constructeur
```cpp
SyscallResolver();
```

#### Méthodes

##### `bool Init()`
Initialise le resolver en parsant ntdll.dll.

**Retour**:
- `true`: Succès (syscalls résolus)
- `false`: Échec

**Exemple**:
```cpp
SyscallResolver resolver;
if (!resolver.Init()) {
    // Erreur
}
```

##### `bool ResolveByName(const char* name, WORD& ssn, PVOID& address)`
Résout un syscall par son nom.

**Paramètres**:
- `name`: Nom de la fonction (ex: "NtAllocateVirtualMemory")
- `ssn`: [OUT] System Service Number
- `address`: [OUT] Adresse de la fonction dans ntdll

**Retour**:
- `true`: Syscall résolu
- `false`: Syscall non trouvé ou optimisé par Windows

**Exemple**:
```cpp
WORD ssn;
PVOID addr;
if (resolver.ResolveByName("NtAllocateVirtualMemory", ssn, addr)) {
    printf("SSN: 0x%04X\n", ssn);
}
```

##### `int GetCount() const`
Retourne le nombre de syscalls résolus.

**Exemple**:
```cpp
printf("Syscalls: %d\n", resolver.GetCount());  // Ex: 512
```

---

### 2. SyscallInvoker

**Responsabilité**: Invoquer un syscall avec son SSN.

#### Méthode Statique

##### `static NTSTATUS Invoke(WORD ssn, PVOID arg1, ..., PVOID arg10)`
Invoque un syscall directement.

**Paramètres**:
- `ssn`: System Service Number
- `arg1...arg10`: Arguments du syscall (optionnels)

**Retour**:
- `NTSTATUS`: Code de statut NT

**Exemple**:
```cpp
WORD ssn = 0x0018;  // NtAllocateVirtualMemory
PVOID baseAddress = nullptr;
SIZE_T size = 4096;

NTSTATUS status = SyscallInvoker::Invoke(
    ssn,
    NtCurrentProcess(),
    &baseAddress,
    0,
    &size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);
```

---

### 3. SyscallWrappers

**Responsabilité**: API haut niveau pour syscalls courants.

#### Constructeur
```cpp
explicit SyscallWrappers(SyscallResolver* resolver);
```

**Paramètre**:
- `resolver`: Pointeur vers un `SyscallResolver` initialisé

#### Méthodes - Gestion Mémoire

##### `PVOID HeapAlloc(SIZE_T size)`
Alloue de la mémoire (équivalent malloc).

**Paramètre**:
- `size`: Taille en bytes

**Retour**:
- Pointeur vers la mémoire allouée, ou `nullptr` si échec

**Exemple**:
```cpp
PVOID mem = wrappers.HeapAlloc(1024);
if (mem) {
    // Utiliser...
    wrappers.HeapFree(mem);
}
```

##### `bool HeapFree(PVOID ptr)`
Libère la mémoire allouée.

**Paramètre**:
- `ptr`: Pointeur à libérer

**Retour**:
- `true`: Succès
- `false`: Échec

##### `PVOID VirtualAlloc(SIZE_T size, DWORD protect)`
Alloue de la mémoire virtuelle.

**Paramètres**:
- `size`: Taille en bytes
- `protect`: Protection mémoire (ex: PAGE_READWRITE, PAGE_EXECUTE_READWRITE)

**Retour**:
- Pointeur vers la mémoire, ou `nullptr`

**Exemple**:
```cpp
PVOID exec = wrappers.VirtualAlloc(4096, PAGE_EXECUTE_READWRITE);
```

##### `bool VirtualFree(PVOID address, SIZE_T size)`
Libère la mémoire virtuelle.

#### Méthodes - Informations Système

##### `DWORD GetCurrentProcessId()`
Retourne le PID du processus courant.

**Exemple**:
```cpp
DWORD pid = wrappers.GetCurrentProcessId();
printf("PID: %lu\n", pid);
```

##### `DWORD GetCurrentThreadId()`
Retourne le TID du thread courant.

##### `QWORD GetSystemTime()`
Retourne le timestamp Unix (secondes depuis 1970).

**Exemple**:
```cpp
QWORD time = wrappers.GetSystemTime();
printf("Unix Time: %llu\n", time);
```

##### `HANDLE GetCurrentProcess()`
Retourne un pseudo-handle du processus courant.

##### `HANDLE GetCurrentThread()`
Retourne un pseudo-handle du thread courant.

#### Méthodes - Fichiers

##### `HANDLE CreateFile(...)`
⚠️ Non implémenté (retourne nullptr).

##### `bool CloseHandle(HANDLE handle)`
Ferme un handle.

**Exemple**:
```cpp
wrappers.CloseHandle(hFile);
```

---

## Types de Base

Définis dans `Types.h`:

```cpp
using BYTE = unsigned char;
using WORD = unsigned short;
using DWORD = unsigned long;
using QWORD = unsigned long long;
using PVOID = void*;
using SIZE_T = unsigned long long;
using HANDLE = void*;
using NTSTATUS = long;

// Macro utile
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
```

---

## Constantes Utiles

### Protection Mémoire
```cpp
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READWRITE 0x40
```

### Allocation Mémoire
```cpp
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_RELEASE 0x8000
```

---

## Exemple Complet

```cpp
#include "whipsyscall/WhipSysCall.h"
#include <stdio.h>

int main() {
    // 1. Initialiser
    SyscallResolver resolver;
    if (!resolver.Init()) {
        return 1;
    }

    SyscallWrappers wrappers(&resolver);

    // 2. Allouer mémoire
    PVOID mem = wrappers.HeapAlloc(4096);
    if (mem) {
        // Utiliser la mémoire
        memset(mem, 0x41, 4096);

        // Libérer
        wrappers.HeapFree(mem);
    }

    // 3. Infos système
    DWORD pid = wrappers.GetCurrentProcessId();
    QWORD time = wrappers.GetSystemTime();

    printf("PID: %lu, Time: %llu\n", pid, time);

    // 4. Appel direct
    WORD ssn;
    PVOID addr;
    if (resolver.ResolveByName("NtDelayExecution", ssn, addr)) {
        // Sleep 100ms
        LARGE_INTEGER delay;
        delay.QuadPart = -1000000;  // 100ms en 100-ns units
        SyscallInvoker::Invoke(ssn, FALSE, &delay);
    }

    return 0;
}
```

---

## Notes Importantes

### Syscalls Optimisés
Certaines fonctions Windows (comme `NtQuerySystemTime`) sont optimisées et n'utilisent pas de vrais syscalls. Elles ne peuvent pas être résolues par `ResolveByName`, mais les wrappers utilisent les mêmes optimisations.

### Portabilité
- ✅ Windows 10/11 x64
- ❌ Windows 7/8 (non testé)
- ❌ x86 32-bit (non supporté)

### Thread-Safety
Les classes ne sont **pas** thread-safe. Créez une instance par thread ou utilisez des mutex.

### Limites
- Maximum 10 arguments par syscall
- Les SSN changent entre versions de Windows (résolution dynamique nécessaire)

---

## Référence Syscalls Windows

Pour la liste complète des syscalls et leurs signatures:
- [Windows NT Syscall Table](https://j00ru.vexillium.org/syscalls/nt/64/)
- [MSDN - Nt Functions](https://docs.microsoft.com/en-us/windows/win32/api/)