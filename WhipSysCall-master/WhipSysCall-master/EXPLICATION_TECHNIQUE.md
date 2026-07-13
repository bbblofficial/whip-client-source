# WhipSysCall - Explication Technique Détaillée

## 📚 Table des matières
1. [Qu'est-ce qu'un syscall?](#quest-ce-quun-syscall)
2. [Pourquoi contourner ntdll?](#pourquoi-contourner-ntdll)
3. [Architecture de WhipSysCall](#architecture-de-whipsyscall)
4. [Flux d'exécution détaillé](#flux-dexécution-détaillé)
5. [Exemples concrets](#exemples-concrets)

---

## Qu'est-ce qu'un syscall?

Un **syscall** (appel système) est un mécanisme permettant à un programme en mode utilisateur de demander un service au kernel Windows.

### Flux normal (avec ntdll.dll)
```
Application
    ↓
kernel32.dll (ex: VirtualAlloc)
    ↓
ntdll.dll (ex: NtAllocateVirtualMemory)
    ↓ [instruction SYSCALL]
Kernel Windows (nt!NtAllocateVirtualMemory)
```

### Flux avec WhipSysCall (direct)
```
Application
    ↓
WhipSysCall (résout le SSN)
    ↓ [instruction SYSCALL directe]
Kernel Windows (nt!NtAllocateVirtualMemory)
```

**Avantage**: On saute ntdll.dll, donc on évite tous les hooks qui y sont installés!

---

## Pourquoi contourner ntdll?

### Problème des hooks
Les solutions de sécurité (EDR, antivirus) installent des **hooks** dans ntdll.dll:

1. **IAT Hooking**: Modifie la Import Address Table
2. **EAT Hooking**: Modifie la Export Address Table
3. **Inline Hooking**: Insère un JMP au début des fonctions

```asm
; Fonction ntdll!NtAllocateVirtualMemory NORMALE:
mov r10, rcx
mov eax, 0x18          ; SSN (Syscall Number)
syscall
ret

; Fonction ntdll!NtAllocateVirtualMemory HOOKÉE:
jmp 0x7FFE12340000     ; Saut vers l'EDR!
nop
nop
...
```

### Solution de WhipSysCall
Au lieu d'appeler `ntdll!NtAllocateVirtualMemory`, on:
1. Extrait le SSN (0x18) en parsant le code de la fonction
2. Appelle directement `syscall` avec ce SSN
3. **Résultat**: L'EDR ne voit rien passer!

---

## Architecture de WhipSysCall

### 1. SyscallResolver.cpp - Le Parser PE

**Objectif**: Extraire les SSN depuis ntdll.dll en mémoire

#### Étapes:
```cpp
1. Trouver ntdll.dll en mémoire
   → Via PEB (Process Environment Block)
   → __readgsqword(0x60) donne l'adresse de la PEB
   → PEB->Ldr->InMemoryOrderModuleList[1] = ntdll

2. Parser l'en-tête PE de ntdll
   → DOS Header (MZ)
   → NT Headers (PE)
   → Export Directory

3. Parcourir la table d'export
   → Pour chaque fonction Nt* / Zw*:
     - Récupérer l'adresse
     - Analyser les opcodes
     - Extraire le SSN

4. Pattern matching des opcodes
   Pattern 1: 4C 8B D1 B8 [XX XX] 00 00  (mov r10,rcx; mov eax,SSN)
   Pattern 2: B8 [XX XX] 00 00 4C 8B D1  (mov eax,SSN; mov r10,rcx)
```

**Exemple d'extraction**:
```
Fonction: ntdll!NtAllocateVirtualMemory @ 0x7FFE0001A230

Opcodes:
  4C 8B D1              ; mov r10, rcx
  B8 18 00 00 00        ; mov eax, 0x18  ← SSN = 0x18 !
  0F 05                 ; syscall
  C3                    ; ret

WhipSysCall extrait: SSN = 0x18
```

### 2. SyscallStub.asm - Le Shellcode

**Objectif**: Effectuer l'appel syscall avec le bon SSN

```asm
SyscallStub PROC
    ; Entrée:
    ;   RCX = SSN (Syscall Number)
    ;   RDX = arg1
    ;   R8  = arg2
    ;   R9  = arg3
    ;   [RSP+28h] = arg4
    ;   etc.

    mov r10, rcx            ; Sauvegarder SSN temporairement
    mov eax, ecx            ; Mettre SSN dans EAX

    ; Décaler les arguments (convention Windows x64)
    mov rcx, rdx            ; arg1 → RCX
    mov rdx, r8             ; arg2 → RDX
    mov r8, r9              ; arg3 → R8
    mov r9, [rsp + 28h]     ; arg4 → R9

    ; arg5+ restent sur la pile

    mov r10, rcx            ; Requis par la convention syscall
    syscall                 ; APPEL DIRECT AU KERNEL!

    ret
SyscallStub ENDP
```

**Pourquoi `mov r10, rcx`?**
- C'est la convention syscall de Windows x64
- Le kernel s'attend à avoir le 1er argument dans R10 (pas RCX)

### 3. SyscallWrappers.cpp - Les Helpers

**Objectif**: API pratiques pour les opérations courantes

```cpp
PVOID SyscallWrappers::HeapAlloc(SIZE_T size) {
    // 1. Résoudre NtAllocateVirtualMemory
    WORD ssn;
    PVOID addr;
    resolver->ResolveByName("NtAllocateVirtualMemory", ssn, addr);

    // 2. Préparer les arguments
    HANDLE hProcess = (HANDLE)-1;  // Current process
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = size;

    // 3. Appeler le syscall
    SyscallInvoker::Invoke(
        ssn,
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    return baseAddress;
}
```

---

## Flux d'exécution détaillé

### Exemple: Allouer 1024 octets

```cpp
SyscallWrappers wrappers(&resolver);
PVOID mem = wrappers.HeapAlloc(1024);
```

#### Étape par étape:

```
1. Application appelle wrappers.HeapAlloc(1024)
   ↓

2. SyscallWrappers::HeapAlloc()
   - Appelle resolver->ResolveByName("NtAllocateVirtualMemory", ssn, addr)
   ↓

3. SyscallResolver::ResolveByName()
   - Calcule hash = FNV1a("NtAllocateVirtualMemory") = 0x3F2A8B9C
   - Cherche dans table[] → trouve ssn = 0x18
   ↓

4. SyscallInvoker::Invoke(0x18, ...)
   - Appelle SyscallStub(0x18, hProcess, &baseAddress, ...)
   ↓

5. SyscallStub (assembleur)
   - mov eax, 0x18        ; Met le SSN dans EAX
   - Arrange les arguments dans RCX, RDX, R8, R9
   - syscall               ; APPEL DIRECT!
   ↓

6. Kernel Windows (nt!NtAllocateVirtualMemory)
   - Alloue la mémoire
   - Retourne l'adresse dans baseAddress
   ↓

7. Retour à l'application
   - mem contient l'adresse de la mémoire allouée
```

---

## Exemples concrets

### Exemple 1: Résolution basique

```cpp
SyscallResolver resolver;
resolver.Init();

WORD ssn;
PVOID address;

if (resolver.ResolveByName("NtQuerySystemTime", ssn, address)) {
    printf("SSN: 0x%04X\n", ssn);        // Ex: 0x005A
    printf("Address: %p\n", address);     // Ex: 0x7FFE00023450
}
```

**Ce qui se passe**:
1. `Init()` parse toute la table d'export de ntdll
2. Remplit `table[]` avec {hash, ssn, address}
3. `ResolveByName()` calcule le hash et cherche dans la table

### Exemple 2: Appel syscall direct

```cpp
// Sleep pendant 1 seconde via NtDelayExecution

WORD ssn;
PVOID addr;
resolver.ResolveByName("NtDelayExecution", ssn, addr);

LARGE_INTEGER delay;
delay.QuadPart = -10000000;  // 1 sec (négatif = relatif, 100-ns units)

SyscallInvoker::Invoke(ssn, FALSE, &delay);
```

**Équivalent normal**:
```cpp
Sleep(1000);  // Via kernel32.dll → ntdll.dll
```

**Avec WhipSysCall**:
- Pas d'import kernel32.lib
- Pas d'appel à ntdll (donc pas de hooks)
- Direct vers le kernel!

### Exemple 3: Allocation mémoire

```cpp
SyscallWrappers wrappers(&resolver);

// Allouer 4096 bytes
PVOID mem = wrappers.HeapAlloc(4096);

// Écrire dedans
memset(mem, 0x41, 4096);  // Remplir de 'A'

// Libérer
wrappers.HeapFree(mem);
```

**Équivalent**:
```cpp
void* mem = malloc(4096);       // CRT
void* mem = VirtualAlloc(...);  // kernel32
void* mem = HeapAlloc(...);     // kernel32
```

---

## Techniques avancées utilisées

### 1. Hashing FNV-1a
Économise la mémoire en stockant un hash 32-bit au lieu du nom complet:

```cpp
constexpr DWORD HashFnv1a(const char* str) {
    DWORD hash = 0x811c9dc5;
    while (*str) {
        hash ^= (BYTE)*str++;
        hash *= 0x01000193;
    }
    return hash;
}

// "NtAllocateVirtualMemory" → 0x3F2A8B9C
```

### 2. Accès PEB direct
Pas besoin de `GetModuleHandle("ntdll.dll")`:

```cpp
#ifdef _WIN64
    BYTE* peb = (BYTE*)__readgsqword(0x60);  // GS:[0x60] = PEB
#else
    BYTE* peb = (BYTE*)__readfsdword(0x30);  // FS:[0x30] = PEB (x86)
#endif

// PEB+0x18 = Ldr
// Ldr+0x10 = InMemoryOrderModuleList
// [1] = ntdll.dll (toujours le 2ème module)
```

### 3. Zero imports
CMake ne lie PAS kernel32.lib par défaut:
- Pas de `GetProcAddress`
- Pas de `LoadLibrary`
- Pas de `VirtualAlloc`
- Tout est résolu manuellement!

---

## Cas d'usage légitimes

✅ **Légaux et éthiques**:
- Recherche en sécurité (analyser des techniques d'évasion)
- Développement d'outils de défense (détecter les appels syscalls directs)
- CTF (Capture The Flag) competitions
- Debugging bas niveau
- Reverse engineering éducatif

❌ **Illégaux**:
- Malware
- Rootkits
- Évasion de sécurité pour actions malveillantes

---

## Ressources

- [Windows NT Syscall Table](https://j00ru.vexillium.org/syscalls/nt/64/)
- [MSDN - Nt Functions](https://docs.microsoft.com/en-us/windows/win32/api/)
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

---

**Auteur**: WhipSysCall Project
**Licence**: Éducatif / Recherche
**Plateforme**: Windows x64 uniquement