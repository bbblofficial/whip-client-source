# WhipMmap

Un outil de manual mapping pour l'injection de DLL sur Windows.

## Description

!! CA UTILISE PAS LA LIB DE SYSCALL MAIS UN SYSCALL INTERNE !!

WhipMmap est un injecteur de DLL utilisant la technique de manual mapping pour charger des bibliothèques dynamiques dans des processus cibles. Cette technique permet de contourner les détections basiques en chargeant manuellement les sections PE et en résolvant les imports sans utiliser `LoadLibrary`.

## Architecture

Le projet est structuré en plusieurs modules :

- **PeParser** : Analyse et traitement des fichiers PE (Portable Executable)
- **ProcessUtils** : Utilitaires pour la manipulation de processus Windows
- **MemoryUtils** : Gestion de la mémoire dans les processus distants
- **LoaderStub** : Stub d'exécution pour le chargement dans le processus cible
- **Syscalls** : Appels système directs pour éviter les hooks userland
- **ManualMapper** : Orchestration du processus de mapping

## Prérequis

- Windows 10/11
- CMake 4.1 ou supérieur
- Compilateur C++20 (MSVC, MinGW, ou Clang)
- CLion ou Visual Studio (recommandé)

## Compilation

### Avec CMake

```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### Avec CLion

1. Ouvrir le projet dans CLion
2. Sélectionner la configuration Release
3. Build → Build Project

## Utilisation

```cpp
#include "ManualMapper/ManualMapper.h"

ManualMapper::ManualMapper mapper;

// Charger l'image DLL
if (!mapper.LoadImage(L"chemin/vers/votre.dll"))
{
    std::wcout << L"Échec du chargement de l'image" << std::endl;
    return 1;
}

// Mapper dans le processus cible
if (!mapper.MapToProcess(L"processus_cible.exe"))
{
    std::wcout << L"Échec du mapping" << std::endl;
    return 1;
}

// Exécuter le point d'entrée
if (!mapper.Execute())
{
    std::wcout << L"Échec de l'exécution" << std::endl;
    return 1;
}

// Décharger proprement
mapper.Unload();
```

## Fonctionnalités

- Manual mapping complet avec résolution des imports
- Support des relocations
- Exécution du point d'entrée (DllMain)
- Appels système directs via syscalls
- Gestion propre du déchargement
- Support des DLL 64-bit

## Avertissement

Cet outil est destiné à des fins éducatives et de recherche en sécurité uniquement. L'utilisation de cet outil sur des systèmes sans autorisation explicite est illégale. L'auteur n'est pas responsable de toute utilisation abusive.

## License

À définir

## Auteur

Java