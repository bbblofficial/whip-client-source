#pragma once
#include <string>
#include <vector>
#include <cstring>

class StringUtils {
public:
    static std::vector<const char*> split(const char* str, const char* delimiter) {
        // On préserve les chaînes dans une variable statique qui persistera
        static std::vector<std::string> stringStorage;
        std::vector<const char*> result;

        // Vider le stockage précédent
        stringStorage.clear();

        if (!str || !delimiter) {
            return result;
        }

        size_t delimLen = strlen(delimiter);
        const char* start = str;
        const char* end;

        while ((end = strstr(start, delimiter)) != nullptr) {
            size_t len = end - start;
            // Créer une copie persistante de la sous-chaîne
            stringStorage.push_back(std::string(start, len));
            // Ajouter un pointeur vers cette copie
            result.push_back(stringStorage.back().c_str());
            start = end + delimLen;
        }

        // Ajouter la dernière partie
        if (*start != '\0') {
            stringStorage.push_back(std::string(start));
            result.push_back(stringStorage.back().c_str());
        }

        return result;
    }

    static bool endsWith(const char* str, const char* suffix) {
        if (str == nullptr || suffix == nullptr)
            return false;

        size_t strLen = strlen(str);
        size_t suffixLen = strlen(suffix);

        if (suffixLen > strLen)
            return false;

        return strcmp(str + strLen - suffixLen, suffix) == 0;
    }
};