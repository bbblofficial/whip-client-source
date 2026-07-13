#pragma once
#include <string>
#include <map>

// Client HTTP natif sans dépendances externes
// Utilise uniquement les sockets POSIX standard
class NativeHTTP {
public:
    struct HTTPResponse {
        int status_code;
        std::string body;
        std::map<std::string, std::string> headers;
        bool success;
    };

    // Effectuer une requête HTTP POST
    static HTTPResponse post(const std::string& url, 
                           const std::string& data,
                           const std::map<std::string, std::string>& headers = {});

    // Effectuer une requête HTTP GET
    static HTTPResponse get(const std::string& url,
                          const std::map<std::string, std::string>& headers = {});

private:
    struct URLComponents {
        std::string protocol;
        std::string host;
        int port;
        std::string path;
        bool is_https;
    };

    // Parser une URL
    static URLComponents parseURL(const std::string& url);
    
    // Créer une connexion socket
    static int createConnection(const std::string& host, int port);
    
    // Envoyer une requête HTTP brute
    static std::string buildHTTPRequest(const std::string& method,
                                      const std::string& path,
                                      const std::string& host,
                                      const std::string& data,
                                      const std::map<std::string, std::string>& headers);
    
    // Lire la réponse HTTP
    static HTTPResponse parseHTTPResponse(const std::string& response);
    
    // Lire toutes les données du socket
    static std::string readAll(int socket_fd, int timeout_ms = 5000);
    
    // Résoudre nom d'hôte en IP
    static std::string resolveHostname(const std::string& hostname);
};