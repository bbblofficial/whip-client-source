#pragma once
#include <cstring>
#include <cstdio>
#include <algorithm>

// Macros sécurisées pour remplacer les fonctions dangereuses
class SafeString {
public:
    // Remplacement sécurisé pour sprintf
    template<typename... Args>
    static int safe_sprintf(char* buffer, size_t buffer_size, const char* format, Args... args) {
        if (!buffer || buffer_size == 0) return -1;
        
        int result = snprintf(buffer, buffer_size, format, args...);
        
        // Assurer la null-termination
        buffer[buffer_size - 1] = '\0';
        
        // Retourner -1 si truncation
        if (result >= static_cast<int>(buffer_size)) {
            return -1;
        }
        
        return result;
    }
    
    // Remplacement sécurisé pour strcpy
    static char* safe_strcpy(char* dest, const char* src, size_t dest_size) {
        if (!dest || !src || dest_size == 0) return nullptr;
        
        size_t src_len = strlen(src);
        size_t copy_len = std::min(src_len, dest_size - 1);
        
        memcpy(dest, src, copy_len);
        dest[copy_len] = '\0';
        
        return dest;
    }
    
    // Remplacement sécurisé pour strcat
    static char* safe_strcat(char* dest, const char* src, size_t dest_size) {
        if (!dest || !src || dest_size == 0) return nullptr;
        
        size_t dest_len = strnlen(dest, dest_size);
        if (dest_len >= dest_size) return nullptr; // dest déjà trop long
        
        size_t remaining = dest_size - dest_len - 1;
        size_t src_len = strlen(src);
        size_t copy_len = std::min(src_len, remaining);
        
        memcpy(dest + dest_len, src, copy_len);
        dest[dest_len + copy_len] = '\0';
        
        return dest;
    }
    
    // Remplacement sécurisé pour memcpy avec validation
    static void* safe_memcpy(void* dest, const void* src, size_t dest_size, size_t copy_size) {
        if (!dest || !src || copy_size == 0) return dest;
        
        // Vérifier que la copie ne dépasse pas la taille du buffer de destination
        if (copy_size > dest_size) {
            copy_size = dest_size;
        }
        
        return memcpy(dest, src, copy_size);
    }
    
    // Validation de longueur de chaîne
    static bool validate_string_length(const char* str, size_t max_length) {
        if (!str) return false;
        return strnlen(str, max_length + 1) <= max_length;
    }
    
    // Copie sécurisée de chaîne avec validation
    static bool safe_string_copy(char* dest, size_t dest_size, const char* src, size_t max_src_len = SIZE_MAX) {
        if (!dest || !src || dest_size == 0) return false;
        
        size_t src_len = strnlen(src, max_src_len);
        if (src_len >= dest_size) return false;
        
        memcpy(dest, src, src_len);
        dest[src_len] = '\0';
        
        return true;
    }
};

// Macros pour faciliter l'usage
#define SAFE_SPRINTF(buffer, format, ...) \
    SafeString::safe_sprintf(buffer, sizeof(buffer), format, ##__VA_ARGS__)

#define SAFE_STRCPY(dest, src) \
    SafeString::safe_strcpy(dest, src, sizeof(dest))

#define SAFE_STRCAT(dest, src) \
    SafeString::safe_strcat(dest, src, sizeof(dest))

#define SAFE_MEMCPY(dest, src, size) \
    SafeString::safe_memcpy(dest, src, sizeof(dest), size)

#define VALIDATE_STRING_LEN(str, max_len) \
    SafeString::validate_string_length(str, max_len)