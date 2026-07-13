// Exemple d'utilisation du NduMemoryCleaner en MODE ACTIF
#include "whipnexus/NduMemoryCleaner.h"
#include "whipnexus/SyscallManager.h"
#include "whipnexus/WhipNexus.h"
#include <iostream>

int main() {
    // Initialiser le syscall manager
    if (!SyscallManager::Init()) {
        std::cout << "[-] Failed to initialize SyscallManager\n";
        return 1;
    }

    std::cout << "[+] SyscallManager initialized\n";

    // ========================================
    // DÉMARRER LE NETTOYAGE ACTIF
    // ========================================
    std::cout << "[*] Starting active network stats cleaning...\n";

    // Nettoie les stats toutes les 500ms (en arrière-plan)
    if (NduMemoryCleaner::StartActiveCleaning(500)) {
        std::cout << "[+] Active cleaning started!\n";
        std::cout << "[+] Your network consumption will stay at 0 in Task Manager\n";
        std::cout << "[+] Even while doing network activities!\n\n";
    } else {
        std::cout << "[-] Failed to start active cleaning\n";
        std::cout << "[-] Make sure you have admin rights\n";
        return 1;
    }

    // ========================================
    // FAIRE TON TRAFIC RÉSEAU ICI
    // ========================================
    std::cout << "[*] Doing network activities...\n";
    std::cout << "[*] Check Task Manager - network usage should stay at 0!\n\n";

    // Exemple: connexion à un serveur
    WhipNexus client;
    if (client.init()) {
        std::cout << "[+] Client initialized\n";

        if (client.connect("127.0.0.1", 8080)) {
            std::cout << "[+] Connected to server\n";

            // Envoyer/recevoir des données
            // Pendant ce temps, le thread de nettoyage efface les stats
            for (int i = 0; i < 100; i++) {
                byte testData[1024];
                SyscallManager::SecureMemSet(testData, 0x41, sizeof(testData));

                // Opcode applicatif neutre 0x10 (Nexus ne connaît pas la sémantique)
                client.sendPacket(0x10, testData, sizeof(testData));

                std::cout << "[*] Sent " << sizeof(testData) << " bytes (iteration " << (i+1) << "/100)\n";
                std::cout << "    -> Task Manager should still show 0 bytes!\n";

                Sleep(100);
            }

            client.disconnect();
            std::cout << "[+] Disconnected\n";
        }
    }

    std::cout << "\n[*] Network activities finished\n";

    // ========================================
    // ARRÊTER LE NETTOYAGE ACTIF
    // ========================================
    std::cout << "[*] Stopping active cleaning...\n";
    NduMemoryCleaner::StopActiveCleaning();
    std::cout << "[+] Active cleaning stopped\n";

    std::cout << "\n[+] Final check: Task Manager should show 0 bytes network usage!\n";

    SyscallManager::Cleanup();
    return 0;
}