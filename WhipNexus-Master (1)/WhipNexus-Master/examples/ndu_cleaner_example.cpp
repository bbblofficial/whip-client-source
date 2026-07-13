// Exemple d'utilisation du NduMemoryCleaner
#include "whipnexus/NduMemoryCleaner.h"
#include "whipnexus/SyscallManager.h"
#include <iostream>

int main() {
    // Initialiser le syscall manager
    if (!SyscallManager::Init()) {
        std::cout << "Failed to initialize SyscallManager\n";
        return 1;
    }

    std::cout << "[+] SyscallManager initialized\n";

    // ========================================
    // Faire ton trafic réseau ici
    // ========================================
    std::cout << "[*] Doing network activities...\n";
    // ... ton code réseau ...

    // ========================================
    // Nettoyer les stats réseau APRÈS
    // ========================================
    std::cout << "[*] Clearing network statistics from NDU memory...\n";

    if (NduMemoryCleaner::ClearCurrentProcessStats()) {
        std::cout << "[+] Successfully cleared network stats!\n";
        std::cout << "[+] Your process network consumption is now hidden from:\n";
        std::cout << "    - Task Manager\n";
        std::cout << "    - Resource Monitor\n";
        std::cout << "    - netstat statistics\n";
    } else {
        std::cout << "[-] Failed to clear network stats\n";
        std::cout << "[-] Make sure you have admin rights\n";
    }

    SyscallManager::Cleanup();
    return 0;
}