# Guide d'Intégration - WhipSysCall

Ce guide explique comment intégrer WhipSysCall dans votre projet C++.

## 📦 Méthodes d'Intégration

### Méthode 1: Bibliothèque Statique (Recommandé)

#### 1. Compiler WhipSysCall

```bash
cd WhipSysCall
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
```

Résultat: `build/Release/WhipSysCall.lib`

#### 2. Copier les Fichiers

Copiez dans votre projet:
```
VotreProjet/
├── libs/
│   └── WhipSysCall.lib          # Bibliothèque compilée
└── include/
    └── whipsyscall/              # Headers
        ├── Types.h
        ├── SyscallResolver.h
        ├── SyscallInvoker.h
        ├── SyscallWrappers.h
        └── WhipSysCall.h
```

#### 3. Configurer CMake

Dans votre `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.15)
project(MonProjet)

set(CMAKE_CXX_STANDARD 20)

# Ajouter les includes WhipSysCall
include_directories(${CMAKE_SOURCE_DIR}/include)

# Ajouter votre exécutable
add_executable(MonProjet main.cpp)

# Linker avec WhipSysCall
target_link_libraries(MonProjet
    PRIVATE
    ${CMAKE_SOURCE_DIR}/libs/WhipSysCall.lib
)
```

#### 4. Utiliser dans le Code

```cpp
#include "whipsyscall/WhipSysCall.h"

int main() {
    SyscallResolver resolver;
    resolver.Init();

    // Votre code...

    return 0;
}
```

---

### Méthode 2: Sous-module Git

#### 1. Ajouter comme Sous-module

```bash
cd VotreProjet
git submodule add https://github.com/votre-repo/WhipSysCall external/WhipSysCall
git submodule update --init --recursive
```

#### 2. Configurer CMake

Dans votre `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.15)
project(MonProjet)

# Ajouter WhipSysCall
add_subdirectory(external/WhipSysCall)

# Votre exécutable
add_executable(MonProjet main.cpp)

# Linker avec WhipSysCall
target_link_libraries(MonProjet PRIVATE WhipSysCall)

# Include directories sont automatiquement propagés
```

---

### Méthode 3: Copie des Sources

#### 1. Copier les Fichiers Source

```
VotreProjet/
├── src/
│   └── whipsyscall/
│       ├── SyscallResolver.cpp
│       ├── SyscallInvoker.cpp
│       ├── SyscallWrappers.cpp
│       └── SyscallStub.asm
└── include/
    └── whipsyscall/
        ├── Types.h
        ├── SyscallResolver.h
        ├── SyscallInvoker.h
        ├── SyscallWrappers.h
        └── WhipSysCall.h
```

#### 2. Configurer CMake

```cmake
cmake_minimum_required(VERSION 3.15)
project(MonProjet LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)

# Sources WhipSysCall
set(WHIPSYSCALL_SOURCES
    src/whipsyscall/SyscallResolver.cpp
    src/whipsyscall/SyscallInvoker.cpp
    src/whipsyscall/SyscallWrappers.cpp
    src/whipsyscall/SyscallStub.asm
)

# Créer la bibliothèque
add_library(WhipSysCall STATIC ${WHIPSYSCALL_SOURCES})
target_include_directories(WhipSysCall PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Votre projet
add_executable(MonProjet main.cpp)
target_link_libraries(MonProjet PRIVATE WhipSysCall)
```

---

## 🔧 Configuration Visual Studio (sans CMake)

### 1. Créer un Projet

1. Ouvrir Visual Studio
2. Créer un nouveau projet C++ (Console App)

### 2. Ajouter les Fichiers

**Propriétés du Projet → C/C++ → Général → Répertoires Include Supplémentaires**:
```
C:\chemin\vers\WhipSysCall\include
```

**Propriétés du Projet → Éditeur de Liens → Général → Répertoires de Bibliothèques Supplémentaires**:
```
C:\chemin\vers\WhipSysCall\build\Release
```

**Propriétés du Projet → Éditeur de Liens → Entrée → Dépendances Supplémentaires**:
```
WhipSysCall.lib
```

### 3. Compiler

Build → Rebuild Solution

---

## 📝 Exemple Complet

### Structure du Projet

```
MonProjet/
├── CMakeLists.txt
├── main.cpp
├── external/
│   └── WhipSysCall/        # Sous-module ou copie
└── build/
```

### CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.15)
project(MonProjet VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# WhipSysCall
add_subdirectory(external/WhipSysCall)

# Mon exécutable
add_executable(MonProjet main.cpp)
target_link_libraries(MonProjet PRIVATE WhipSysCall)

# Options de compilation
if(MSVC)
    target_compile_options(MonProjet PRIVATE /W4)
endif()
```

### main.cpp

```cpp
#include "whipsyscall/WhipSysCall.h"
#include <iostream>

class MyApp {
private:
    SyscallResolver resolver;
    SyscallWrappers wrappers;

public:
    MyApp() : wrappers(&resolver) {
        if (!resolver.Init()) {
            throw std::runtime_error("Failed to initialize WhipSysCall");
        }
    }

    void run() {
        std::cout << "PID: " << wrappers.GetCurrentProcessId() << std::endl;

        // Allouer mémoire
        PVOID mem = wrappers.HeapAlloc(4096);
        if (mem) {
            // Utiliser...
            wrappers.HeapFree(mem);
        }
    }
};

int main() {
    try {
        MyApp app;
        app.run();
    } catch (const std::exception& e) {
        std::cerr << "Erreur: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
```

### Build et Exécution

```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
.\Release\MonProjet.exe
```

---

## 🐛 Dépannage

### Erreur: "intrin.h not found"

**Solution**: Installez le SDK Windows via Visual Studio Installer.

### Erreur: "LNK1104: cannot open file 'kernel32.lib'"

**Solution**: Configurez les chemins SDK dans CMake:
```cmake
set(CMAKE_SYSTEM_VERSION 10.0)
```

### Erreur: "SyscallStub.asm not compiled"

**Solution**: Assurez-vous que MASM est activé:
```cmake
project(MonProjet LANGUAGES CXX ASM_MASM)
```

### Warning: "function can be made static"

**Solution**: Ignorez ou utilisez:
```cmake
target_compile_options(WhipSysCall PRIVATE /wd4505)
```

---

## ⚡ Optimisations

### Release Build

```cmake
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(WhipSysCall PRIVATE /O2 /GL)
    target_link_options(WhipSysCall PRIVATE /LTCG)
endif()
```

### Taille Minimale

```cmake
target_compile_options(WhipSysCall PRIVATE /Os)
```

---

## 🔒 Considérations de Sécurité

### 1. Vérification à l'Initialisation

```cpp
SyscallResolver resolver;
if (!resolver.Init()) {
    // Log l'erreur
    std::cerr << "WhipSysCall init failed!" << std::endl;
    return 1;
}

// Vérifier qu'on a assez de syscalls
if (resolver.GetCount() < 400) {
    std::cerr << "Too few syscalls resolved!" << std::endl;
    return 1;
}
```

### 2. Gestion d'Erreurs

```cpp
PVOID mem = wrappers.HeapAlloc(size);
if (!mem) {
    // Fallback vers malloc standard
    mem = malloc(size);
}
```

### 3. Thread-Safety

```cpp
// Créer une instance par thread
thread_local SyscallResolver resolver;
thread_local SyscallWrappers wrappers(&resolver);
```

---

## 📚 Ressources Supplémentaires

- [API Reference](API.md)
- [README](README.md)
- [Détails Techniques](EXPLICATION_TECHNIQUE.md)

---

**Besoin d'aide?** Ouvrez une issue sur GitHub.