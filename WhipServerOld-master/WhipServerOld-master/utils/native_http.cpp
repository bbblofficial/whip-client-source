#include "native_http.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <cstring>
#include <sstream>
#include <iostream>
#include <algorithm>

NativeHTTP::URLComponents NativeHTTP::parseURL(const std::string& url) {
    URLComponents components;
    
    // Protocole par défaut
    components.protocol = "http";
    components.port = 80;
    components.is_https = false;
    
    std::string remaining = url;
    
    // Extraire le protocole
    size_t protocol_pos = remaining.find("://");
    if (protocol_pos != std::string::npos) {
        components.protocol = remaining.substr(0, protocol_pos);
        remaining = remaining.substr(protocol_pos + 3);
        
        if (components.protocol == "https") {
            components.port = 443;
            components.is_https = true;
        }
    }
    
    // Extraire host et port
    size_t path_pos = remaining.find('/');
    std::string host_part = remaining.substr(0, path_pos);
    
    if (path_pos != std::string::npos) {
        components.path = remaining.substr(path_pos);
    } else {
        components.path = "/";
    }
    
    // Extraire le port du host
    size_t port_pos = host_part.find(':');
    if (port_pos != std::string::npos) {
        components.host = host_part.substr(0, port_pos);
        components.port = std::stoi(host_part.substr(port_pos + 1));
    } else {
        components.host = host_part;
    }
    
    return components;
}

std::string NativeHTTP::resolveHostname(const std::string& hostname) {
    struct hostent* host_entry = gethostbyname(hostname.c_str());
    if (host_entry == nullptr) {
        return "";
    }
    
    struct in_addr addr;
    memcpy(&addr, host_entry->h_addr_list[0], host_entry->h_length);
    return inet_ntoa(addr);
}

int NativeHTTP::createConnection(const std::string& host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    // Résoudre l'adresse IP
    std::string ip = resolveHostname(host);
    if (ip.empty()) {
        close(sock);
        return -1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_aton(ip.c_str(), &server_addr.sin_addr) == 0) {
        close(sock);
        return -1;
    }
    
    // Configurer timeout pour la connexion
    struct timeval timeout;
    timeout.tv_sec = 10;  // 10 secondes
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return -1;
    }
    
    return sock;
}

std::string NativeHTTP::buildHTTPRequest(const std::string& method,
                                        const std::string& path,
                                        const std::string& host,
                                        const std::string& data,
                                        const std::map<std::string, std::string>& headers) {
    std::ostringstream request;
    
    // Ligne de requête
    request << method << " " << path << " HTTP/1.1\r\n";
    
    // Headers obligatoires
    request << "Host: " << host << "\r\n";
    request << "User-Agent: AuthServer/1.0\r\n";
    request << "Connection: close\r\n";
    
    // Content-Length pour POST
    if (method == "POST" && !data.empty()) {
        request << "Content-Length: " << data.length() << "\r\n";
    }
    
    // Headers personnalisés
    for (const auto& header : headers) {
        request << header.first << ": " << header.second << "\r\n";
    }
    
    // Fin des headers
    request << "\r\n";
    
    // Corps de la requête
    if (!data.empty()) {
        request << data;
    }
    
    return request.str();
}

std::string NativeHTTP::readAll(int socket_fd, int timeout_ms) {
    std::string result;
    char buffer[4096];
    
    // Configuration du timeout
    fd_set read_fds;
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    
    while (true) {
        FD_ZERO(&read_fds);
        FD_SET(socket_fd, &read_fds);
        
        int select_result = select(socket_fd + 1, &read_fds, nullptr, nullptr, &timeout);
        
        if (select_result <= 0) {
            // Timeout ou erreur
            break;
        }
        
        ssize_t bytes_read = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read <= 0) {
            // Connexion fermée ou erreur
            break;
        }
        
        buffer[bytes_read] = '\0';
        result.append(buffer, bytes_read);
        
        // Réduire le timeout pour les lectures suivantes
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
    }
    
    return result;
}

NativeHTTP::HTTPResponse NativeHTTP::parseHTTPResponse(const std::string& response) {
    HTTPResponse result;
    result.success = false;
    result.status_code = 0;
    
    if (response.empty()) {
        return result;
    }
    
    // Séparer headers et body
    size_t header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return result;
    }
    
    std::string headers_part = response.substr(0, header_end);
    result.body = response.substr(header_end + 4);
    
    // Parser la ligne de statut
    size_t first_line_end = headers_part.find("\r\n");
    if (first_line_end != std::string::npos) {
        std::string status_line = headers_part.substr(0, first_line_end);
        
        // Extraire le code de statut (format: HTTP/1.1 200 OK)
        std::istringstream status_stream(status_line);
        std::string http_version, status_code_str;
        status_stream >> http_version >> status_code_str;
        
        try {
            result.status_code = std::stoi(status_code_str);
            result.success = (result.status_code >= 200 && result.status_code < 300);
        } catch (...) {
            result.status_code = 0;
        }
        
        // Parser les headers
        std::istringstream headers_stream(headers_part.substr(first_line_end + 2));
        std::string line;
        
        while (std::getline(headers_stream, line) && !line.empty()) {
            // Supprimer \r si présent
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            
            size_t colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                std::string name = line.substr(0, colon_pos);
                std::string value = line.substr(colon_pos + 1);
                
                // Supprimer les espaces
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);
                
                result.headers[name] = value;
            }
        }
    }
    
    return result;
}

NativeHTTP::HTTPResponse NativeHTTP::post(const std::string& url,
                                         const std::string& data,
                                         const std::map<std::string, std::string>& headers) {
    HTTPResponse result;
    result.success = false;
    
    URLComponents components = parseURL(url);
    
    // Vérifier HTTPS (non supporté dans cette implémentation simple)
    if (components.is_https) {
        std::cerr << "[NativeHTTP] HTTPS not supported in this simple implementation" << std::endl;
        return result;
    }
    
    int sock = createConnection(components.host, components.port);
    if (sock < 0) {
        std::cerr << "[NativeHTTP] Failed to connect to " << components.host << ":" << components.port << std::endl;
        return result;
    }
    
    std::string request = buildHTTPRequest("POST", components.path, components.host, data, headers);
    
    // Envoyer la requête
    ssize_t sent = send(sock, request.c_str(), request.length(), 0);
    if (sent < 0) {
        std::cerr << "[NativeHTTP] Failed to send request" << std::endl;
        close(sock);
        return result;
    }
    
    // Lire la réponse
    std::string response = readAll(sock, 10000);  // 10 secondes timeout
    close(sock);
    
    result = parseHTTPResponse(response);
    
    if (result.success) {
        std::cout << "[NativeHTTP] POST to " << url << " - Status: " << result.status_code << std::endl;
    } else {
        std::cerr << "[NativeHTTP] POST to " << url << " failed - Status: " << result.status_code << std::endl;
    }
    
    return result;
}

NativeHTTP::HTTPResponse NativeHTTP::get(const std::string& url,
                                        const std::map<std::string, std::string>& headers) {
    HTTPResponse result;
    result.success = false;
    
    URLComponents components = parseURL(url);
    
    // Vérifier HTTPS (non supporté)
    if (components.is_https) {
        std::cerr << "[NativeHTTP] HTTPS not supported in this simple implementation" << std::endl;
        return result;
    }
    
    int sock = createConnection(components.host, components.port);
    if (sock < 0) {
        std::cerr << "[NativeHTTP] Failed to connect to " << components.host << ":" << components.port << std::endl;
        return result;
    }
    
    std::string request = buildHTTPRequest("GET", components.path, components.host, "", headers);
    
    // Envoyer la requête
    ssize_t sent = send(sock, request.c_str(), request.length(), 0);
    if (sent < 0) {
        std::cerr << "[NativeHTTP] Failed to send request" << std::endl;
        close(sock);
        return result;
    }
    
    // Lire la réponse
    std::string response = readAll(sock, 10000);  // 10 secondes timeout
    close(sock);
    
    result = parseHTTPResponse(response);
    
    if (result.success) {
        std::cout << "[NativeHTTP] GET to " << url << " - Status: " << result.status_code << std::endl;
    } else {
        std::cerr << "[NativeHTTP] GET to " << url << " failed - Status: " << result.status_code << std::endl;
    }
    
    return result;
}