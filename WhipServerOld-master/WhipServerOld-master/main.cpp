#include "Tls_Server.h"
#include <iostream>
#include "utils/SimpleWebhook.h" // Ajout de l'inclusion

#ifdef _WIN32
    #include <windows.h>
    BOOL WINAPI ConsoleHandler(DWORD signal) {
        if (signal == CTRL_C_EVENT) {
            std::cout << "\nShutting down server..." << std::endl;
            Server::getInstance()->stop();
            return TRUE;
        }
        return FALSE;
    }
#else
    #include <signal.h>
    #include <unistd.h>
    void signalHandler(int signum) {
        if (signum == SIGINT || signum == SIGTERM) {
            std::cout << "\nShutting down server..." << std::endl;
            Server::getInstance()->stop();
        }
    }
#endif

int main() {
    try {
        // Test du webhook au d�marrage (optionnel)
        std::cout << "Testing Discord webhook..." << std::endl;
        bool webhookResult = TestWebhook();
        std::cout << "Webhook test " << (webhookResult ? "successful" : "failed") << std::endl;

#ifdef _WIN32
        SetConsoleCtrlHandler(ConsoleHandler, TRUE);
#else
        // Configuration des gestionnaires de signaux pour Linux
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        signal(SIGPIPE, SIG_IGN); // Ignorer SIGPIPE pour éviter les crashes sur déconnexion client
#endif
        Server::getInstance()->start();
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}