#pragma once
#include <cstring>
#include <cstdint>
#include "Protocol/protocol.h"

class InputValidator {
public:
    // Deprecated validation functions removed (validateAuthPayload and validateHeartbeatPayload)
    // These functions used deprecated struct types that no longer exist
    
    static bool validateConfigRequest(const ConfigRequest& request) {
        // Vérifier null-termination
        if (!isNullTerminated(request.sessionToken, sizeof(request.sessionToken))) {
            return false;
        }
        
        if (!isNullTerminated(request.configName, sizeof(request.configName))) {
            return false;
        }
        
        // Vérifier les longueurs
        if (strnlen(request.sessionToken, sizeof(request.sessionToken)) >= sizeof(request.sessionToken)) {
            return false;
        }
        
        if (strnlen(request.configName, sizeof(request.configName)) >= sizeof(request.configName)) {
            return false;
        }
        
        // Vérifier la taille des données (éviter DoS)
        if (request.dataSize > 10 * 1024 * 1024) { // Max 10MB
            return false;
        }
        
        return true;
    }
    
    // Validation générale de chaîne
    static bool validateString(const char* str, size_t max_length, bool allow_empty = true) {
        if (!str) return false;
        
        size_t len = strnlen(str, max_length + 1);
        if (len > max_length) return false;
        
        if (!allow_empty && len == 0) return false;
        
        // Vérifier les caractères non imprimables dangereux
        for (size_t i = 0; i < len; i++) {
            unsigned char c = static_cast<unsigned char>(str[i]);
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
                return false; // Caractères de contrôle dangereux
            }
        }
        
        return true;
    }
    
    // Validation HWID spécifique
    static bool validateHWID(const char* hwid) {
        if (!hwid) return false;
        
        size_t len = strnlen(hwid, 513); // +1 pour détecter overflow
        if (len == 0 || len > 512) return false;
        
        // HWID doit être hexadecimal
        for (size_t i = 0; i < len; i++) {
            char c = hwid[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }
        
        return true;
    }
    
    // Validation session token
    static bool validateSessionToken(const char* token) {
        if (!token) return false;
        
        size_t len = strnlen(token, 641); // +1 pour détecter overflow
        if (len == 0 || len > 640) return false;
        
        // Session token peut contenir alphanumeric + quelques caractères spéciaux
        for (size_t i = 0; i < len; i++) {
            char c = token[i];
            if (!((c >= '0' && c <= '9') || 
                  (c >= 'a' && c <= 'z') || 
                  (c >= 'A' && c <= 'Z') || 
                  c == '+' || c == '/' || c == '=' || c == ':')) {
                return false;
            }
        }
        
        return true;
    }
    
private:
    // Vérifier qu'une chaîne de taille fixe est null-terminée
    static bool isNullTerminated(const char* str, size_t buffer_size) {
        if (!str || buffer_size == 0) return false;
        
        for (size_t i = 0; i < buffer_size; i++) {
            if (str[i] == '\0') {
                return true;
            }
        }
        return false; // Pas de null terminator trouvé
    }
};