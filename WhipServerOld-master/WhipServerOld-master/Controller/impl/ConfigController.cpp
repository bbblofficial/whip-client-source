#include "configController.h"
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "../../utils/json/nlohmann/json.hpp"
#include "../../utils/time_utils.h"
#include <iostream>
#include <random>

// Définir strdup pour la compatibilité Linux
#ifndef _WIN32
#define _strdup strdup
#endif

const std::string ConfigController::CONFIG_BASE_DIR = "configs";

ConfigController::ConfigController() {
    // Cr�er le dossier de configurations s'il n'existe pas
    std::filesystem::create_directories(CONFIG_BASE_DIR);
    std::cout << "[ConfigController] Initialized. Base directory: " << CONFIG_BASE_DIR << std::endl;
}

char* ConfigController::createSafeResponse(const ConfigResponse& response, const void* data, size_t dataSize) {
    // Calculer la taille totale
    size_t totalSize = sizeof(ConfigResponse);
    if (data && dataSize > 0) {
        totalSize += dataSize;
    }

    // Allouer la m�moire
    char* buffer = new char[totalSize];

    // IMPORTANT: Initialiser tout le buffer � z�ro d'abord
    memset(buffer, 0, totalSize);

    // Copier l'en-t�te de r�ponse CHAMP PAR CHAMP pour �viter les probl�mes d'alignement
    ConfigResponse* responsePtr = reinterpret_cast<ConfigResponse*>(buffer);
    responsePtr->status = response.status;
    responsePtr->dataSize = response.dataSize;

    // Initialiser explicitement les champs reserved � z�ro
    memset(responsePtr->reserved, 0, sizeof(responsePtr->reserved));

    // Copier les donn�es si pr�sentes
    if (data && dataSize > 0) {
        memcpy(buffer + sizeof(ConfigResponse), data, dataSize);
    }

    return buffer;
}

std::string ConfigController::getConfigFilePath(const char* hwid, const char* configName) {
    std::string configDir = CONFIG_BASE_DIR + "/" + std::string(hwid);
    std::filesystem::create_directories(configDir);
    return configDir + "/" + std::string(configName) + ".json";
}

std::string ConfigController::listUserConfigs(const char* hwid) {
    std::cout << "[ConfigController] Listing configs for HWID: " << hwid << std::endl;

    std::string configDir = CONFIG_BASE_DIR + "/" + std::string(hwid);
    std::vector<ConfigMetadata> configs;

    if (std::filesystem::exists(configDir)) {
        for (const auto& entry : std::filesystem::directory_iterator(configDir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                try {
                    std::ifstream file(entry.path());
                    if (file.is_open()) {
                        nlohmann::json configJson;
                        file >> configJson;

                        ConfigMetadata metadata{};

                        std::string name = configJson["name"];
                        std::string description = configJson["description"];

                        strncpy(metadata.name, name.c_str(), sizeof(metadata.name) - 1);
                        strncpy(metadata.description, description.c_str(), sizeof(metadata.description) - 1);

                        metadata.timestamp = configJson["timestamp"];

                        // Obtenir la taille des donn�es
                        std::vector<uint8_t> data = configJson["data"].get<std::vector<uint8_t>>();
                        metadata.size = data.size();

                        configs.push_back(metadata);

                        std::cout << "[ConfigController] Found config: " << name << ", size: " << metadata.size << " bytes" << std::endl;
                    }
                }
                catch (const std::exception& e) {
                    std::cerr << "[ConfigController] Error reading config file: " << entry.path() << ": " << e.what() << std::endl;
                    // Ignorer les fichiers corrompus
                }
            }
        }
    }

    // S�rialiser les m�tadonn�es
    std::vector<uint8_t> result(sizeof(uint32_t) + configs.size() * sizeof(ConfigMetadata));
    uint32_t count = static_cast<uint32_t>(configs.size());

    memcpy(result.data(), &count, sizeof(uint32_t));

    for (size_t i = 0; i < configs.size(); i++) {
        memcpy(result.data() + sizeof(uint32_t) + i * sizeof(ConfigMetadata),
            &configs[i], sizeof(ConfigMetadata));
    }

    std::cout << "[ConfigController] Returning " << count << " config(s)" << std::endl;

    // Convertir en cha�ne
    return std::string(reinterpret_cast<char*>(result.data()), result.size());
}

bool ConfigController::saveUserConfig(const char* hwid, const char* configName,
    const char* description, const char* data, size_t dataSize) {
    try {
        std::string configPath = getConfigFilePath(hwid, configName);
        std::cout << "[ConfigController] Saving config: " << configName << " to " << configPath << std::endl;

        nlohmann::json configJson;
        configJson["name"] = configName;
        configJson["description"] = description;
        configJson["timestamp"] = TimeUtils::getUnixTimestamp();

        // Convertir les donn�es binaires en tableau d'octets
        std::vector<uint8_t> dataBytes(data, data + dataSize);
        configJson["data"] = dataBytes;

        std::ofstream file(configPath);
        if (!file.is_open()) {
            std::cerr << "[ConfigController] Failed to open file for writing: " << configPath << std::endl;
            return false;
        }

        file << configJson.dump(4); // Indentation de 4 espaces
        std::cout << "[ConfigController] Config saved successfully: " << configName << ", " << dataSize << " bytes" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[ConfigController] Error saving config: " << e.what() << std::endl;
        return false;
    }
}

bool ConfigController::loadUserConfig(const char* hwid, const char* configName,
    std::string& description, std::vector<uint8_t>& data) {
    try {
        std::string configPath = getConfigFilePath(hwid, configName);
        std::cout << "[ConfigController] Loading config: " << configName << " from " << configPath << std::endl;

        if (!std::filesystem::exists(configPath)) {
            std::cerr << "[ConfigController] Config file not found: " << configPath << std::endl;
            return false;
        }

        std::ifstream file(configPath);
        if (!file.is_open()) {
            std::cerr << "[ConfigController] Failed to open file for reading: " << configPath << std::endl;
            return false;
        }

        nlohmann::json configJson;
        file >> configJson;

        description = configJson["description"];
        data = configJson["data"].get<std::vector<uint8_t>>();

        std::cout << "[ConfigController] Config loaded successfully: " << configName
            << ", description: '" << description << "', data size: " << data.size() << " bytes" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[ConfigController] Error loading config: " << e.what() << std::endl;
        return false;
    }
}

bool ConfigController::deleteUserConfig(const char* hwid, const char* configName) {
    try {
        std::string configPath = getConfigFilePath(hwid, configName);
        std::cout << "[ConfigController] Deleting config: " << configName << " at " << configPath << std::endl;

        if (!std::filesystem::exists(configPath)) {
            std::cerr << "[ConfigController] Config file not found: " << configPath << std::endl;
            return false;
        }

        // NOUVEAU : V�rifier si c'est une config t�l�charg�e et supprimer l'enregistrement
        std::string description;
        std::vector<uint8_t> data;
        if (loadUserConfig(hwid, configName, description, data)) {
            // Chercher le share code dans la description
            size_t sharePos = description.find("Share: ");
            if (sharePos != std::string::npos) {
                std::string shareCode = description.substr(sharePos + 7); // "Share: " = 7 caract�res

                // Nettoyer le share code (enlever les caract�res en trop)
                size_t endPos = shareCode.find_first_of(" \n\r\t");
                if (endPos != std::string::npos) {
                    shareCode = shareCode.substr(0, endPos);
                }

                // Supprimer l'enregistrement de t�l�chargement
                removeUserDownloadRecord(hwid, shareCode.c_str());
                std::cout << "[ConfigController] Removed download record for share code: " << shareCode << std::endl;
            }
        }

        bool result = std::filesystem::remove(configPath);
        if (result) {
            std::cout << "[ConfigController] Config deleted successfully: " << configName << std::endl;
        }
        else {
            std::cerr << "[ConfigController] Failed to delete config: " << configName << std::endl;
        }
        return result;
    }
    catch (const std::exception& e) {
        std::cerr << "[ConfigController] Error deleting config: " << e.what() << std::endl;
        return false;
    }
}

bool ConfigController::modifyUserConfig(const char* hwid, const char* configName,
    const char* newDescription, const char* newData, size_t newDataSize) {
    try {
        std::string configPath = getConfigFilePath(hwid, configName);
        std::cout << "[ConfigController] Modifying config: " << configName << " at " << configPath << std::endl;

        if (!std::filesystem::exists(configPath)) {
            std::cerr << "[ConfigController] Config file not found: " << configPath << std::endl;
            return false;
        }

        // Charger le fichier existant pour pr�server certaines m�tadonn�es
        std::ifstream inFile(configPath);
        if (!inFile.is_open()) {
            std::cerr << "[ConfigController] Failed to open file for reading: " << configPath << std::endl;
            return false;
        }

        nlohmann::json configJson;
        inFile >> configJson;
        inFile.close();

        // Mettre � jour les donn�es
        configJson["description"] = newDescription;
        configJson["timestamp"] = TimeUtils::getUnixTimestamp();

        // Convertir les nouvelles donn�es en tableau d'octets
        std::vector<uint8_t> dataBytes(newData, newData + newDataSize);
        configJson["data"] = dataBytes;

        // �crire le fichier mis � jour
        std::ofstream outFile(configPath);
        if (!outFile.is_open()) {
            std::cerr << "[ConfigController] Failed to open file for writing: " << configPath << std::endl;
            return false;
        }

        outFile << configJson.dump(4);
        std::cout << "[ConfigController] Config modified successfully: " << configName << ", new size: " << newDataSize << " bytes" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[ConfigController] Error modifying config: " << e.what() << std::endl;
        return false;
    }
}

enum class ConfigPublicOperation : uint8_t {
    PUBLISH = 10,      // Publier une config priv�e
    LIST_PUBLIC = 11,  // Lister toutes les configs publiques
    DOWNLOAD = 12,     // T�l�charger une config publique
    RATE = 13          // Noter une config publique
};

// Structure pour les statistiques des configurations publiques
struct PublicConfigStats {
    uint32_t totalConfigs;
    uint32_t totalDownloads;
    uint32_t totalLikes;
    uint32_t totalDislikes;
    uint32_t activeUsers;
    uint32_t lastUpdateTimestamp;
};

// Utilitaire de journalisation propre au ConfigController
void ConfigController::logMessage(const std::string& message) {
    std::cout << "[ConfigController] " << message << std::endl;
}

const std::string ConfigController::PUBLIC_CONFIG_BASE_DIR = "public_configs";

// Fonction pour g�n�rer un code de partage unique pour les configurations publiques
std::string ConfigController::generateShareCode() {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    result.resize(12);  // 12 caract�res de longueur

    // Initialiser le g�n�rateur de nombres al�atoires
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

    // G�n�rer un code al�atoire
    for (int i = 0; i < 12; ++i) {
        result[i] = charset[dis(gen)];
    }

    return result;
}

// Fonction pour publier une configuration utilisateur
bool ConfigController::publishUserConfig(const char* hwid, const char* configName,
    const char* creator, bool allowAnonymous) {
    try {
        // Cr�er le dossier des configurations publiques s'il n'existe pas
        std::filesystem::create_directories(PUBLIC_CONFIG_BASE_DIR);

        // Charger la configuration priv�e
        std::string description;
        std::vector<uint8_t> data;
        if (!loadUserConfig(hwid, configName, description, data)) {
            std::cerr << "[ConfigController] Cannot publish config - not found: " << configName << std::endl;
            return false;
        }

        // G�n�rer un code de partage unique
        std::string shareCode = generateShareCode();
        while (std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR + "/" + shareCode + ".json")) {
            shareCode = generateShareCode();  // R�g�n�rer si le code existe d�j�
        }

        // MODIFICATION : Obtenir automatiquement le vrai nom d'utilisateur � partir du HWID
        std::string realCreator = getUsernameFromHwid(hwid);

        // D�terminer le cr�ateur affich� selon les param�tres
        std::string displayCreator;
        if (allowAnonymous) {
            displayCreator = "Anonymous";
        }
        else {
            // Si creator est fourni et non vide, l'utiliser, sinon utiliser le vrai nom
            if (creator && creator[0] != '\0' && strcmp(creator, "Anonymous") != 0) {
                displayCreator = creator;
            }
            else {
                displayCreator = realCreator; // Utiliser le vrai nom d'utilisateur
            }
        }

        // Cr�er un objet JSON pour la configuration publique
        nlohmann::json configJson;
        configJson["name"] = configName;
        configJson["description"] = description;

        // Stocker toujours le vrai cr�ateur dans real_creator
        configJson["real_creator"] = realCreator;

        // Afficher selon les param�tres
        configJson["creator"] = displayCreator;

        configJson["date"] = TimeUtils::formatTime(std::time(nullptr));
        configJson["share_code"] = shareCode;
        configJson["likes"] = 0;
        configJson["dislikes"] = 0;
        configJson["downloads"] = 0;
        configJson["data"] = data;

        // Ajouter des m�tadonn�es suppl�mentaires
        configJson["hwid"] = hwid;
        configJson["is_anonymous"] = allowAnonymous;

        // Sauvegarder dans le fichier
        std::string configPath = PUBLIC_CONFIG_BASE_DIR + "/" + shareCode + ".json";
        std::ofstream file(configPath);
        if (!file.is_open()) {
            std::cerr << "[ConfigController] Failed to create public config file: " << configPath << std::endl;
            return false;
        }

        file << configJson.dump(4);
        std::cout << "[ConfigController] Config published successfully: " << configName
            << " with share code: " << shareCode
            << " (real creator: " << realCreator
            << ", display: " << displayCreator
            << ", anonymous: " << (allowAnonymous ? "yes" : "no") << ")" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[ConfigController] Error publishing config: " << e.what() << std::endl;
        return false;
    }
}

// Fonction pour charger une configuration publique
bool ConfigController::loadPublicConfig(const char* shareCode, std::string& name, std::string& description,
    std::string& creator, std::string& date, std::vector<uint8_t>& data) {
    try {
        std::string configPath = PUBLIC_CONFIG_BASE_DIR + "/" + shareCode + ".json";

        if (!std::filesystem::exists(configPath)) {
            std::cerr << "[ConfigController] Public config not found: " << shareCode << std::endl;
            return false;
        }

        std::ifstream file(configPath);
        if (!file.is_open()) {
            std::cerr << "[ConfigController] Failed to open public config: " << configPath << std::endl;
            return false;
        }

        nlohmann::json configJson;
        file >> configJson;

        name = configJson["name"];
        description = configJson["description"];
        creator = configJson["creator"];
        date = configJson["date"];
        data = configJson["data"].get<std::vector<uint8_t>>();

        // Incr�menter le compteur de t�l�chargements
        configJson["downloads"] = configJson["downloads"].get<int>() + 1;

        // Sauvegarder le fichier mis � jour
        file.close();
        std::ofstream outFile(configPath);
        outFile << configJson.dump(4);

        std::cout << "[ConfigController] Public config loaded: " << shareCode
            << ", downloads: " << configJson["downloads"].get<int>() << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[ConfigController] Error loading public config: " << e.what() << std::endl;
        return false;
    }
}

// Fonction pour lister toutes les configurations publiques
const char* ConfigController::listPublicConfigs() {
    try {
        // Parcourir le dossier des configurations publiques
        std::vector<PublicConfigInfo> configs;
        uint32_t totalDownloads = 0;  // Compteur pour le total des t�l�chargements
        uint32_t totalLikes = 0;      // Compteur pour le total des likes
        uint32_t totalDislikes = 0;   // Compteur pour le total des dislikes

        if (std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR)) {
            for (const auto& entry : std::filesystem::directory_iterator(PUBLIC_CONFIG_BASE_DIR)) {
                if (entry.is_regular_file() && entry.path().extension() == ".json") {
                    try {
                        std::ifstream file(entry.path());
                        if (file.is_open()) {
                            nlohmann::json configJson;
                            file >> configJson;

                            PublicConfigInfo info;
                            // Initialiser � z�ro pour �viter des valeurs al�atoires
                            memset(&info, 0, sizeof(PublicConfigInfo));

                            std::string name = configJson["name"];
                            std::string description = configJson["description"];

                            // MODIFICATION: Utiliser toujours le champ "creator" pour l'affichage public
                            // (qui contient "Anonymous" pour les configs anonymes)
                            std::string creator = configJson["creator"];

                            std::string date = configJson["date"];
                            std::string shareCode = configJson["share_code"];

                            strncpy(info.name, name.c_str(), sizeof(info.name) - 1);
                            info.name[sizeof(info.name) - 1] = '\0';

                            strncpy(info.description, description.c_str(), sizeof(info.description) - 1);
                            info.description[sizeof(info.description) - 1] = '\0';

                            strncpy(info.creator, creator.c_str(), sizeof(info.creator) - 1);
                            info.creator[sizeof(info.creator) - 1] = '\0';

                            strncpy(info.date, date.c_str(), sizeof(info.date) - 1);
                            info.date[sizeof(info.date) - 1] = '\0';

                            strncpy(info.share_code, shareCode.c_str(), sizeof(info.share_code) - 1);
                            info.share_code[sizeof(info.share_code) - 1] = '\0';

                            // Lire les compteurs avec v�rification pour les fichiers potentiellement incorrects
                            if (configJson.contains("likes") && configJson["likes"].is_number()) {
                                info.likes = configJson["likes"];
                                totalLikes += info.likes;  // Ajouter au total
                            }
                            else {
                                info.likes = 0;
                            }

                            if (configJson.contains("dislikes") && configJson["dislikes"].is_number()) {
                                info.dislikes = configJson["dislikes"];
                                totalDislikes += info.dislikes;  // Ajouter au total
                            }
                            else {
                                info.dislikes = 0;
                            }

                            if (configJson.contains("downloads") && configJson["downloads"].is_number()) {
                                info.downloads = configJson["downloads"];
                                totalDownloads += info.downloads;  // Ajouter au total
                            }
                            else {
                                info.downloads = 0;
                            }

                            configs.push_back(info);

                            // Log pour d�bogage - afficher les informations du cr�ateur
                            std::cout << "[ConfigController] Config: " << name
                                << ", Display creator: " << creator;

                            // Afficher le vrai cr�ateur si diff�rent (pour les configs anonymes)
                            if (configJson.contains("real_creator")) {
                                std::string realCreator = configJson["real_creator"];
                                if (realCreator != creator) {
                                    std::cout << ", Real creator: " << realCreator;
                                }
                            }

                            std::cout << ", Downloads: " << info.downloads
                                << ", Likes: " << info.likes
                                << ", Dislikes: " << info.dislikes << std::endl;
                        }
                    }
                    catch (const std::exception& e) {
                        std::cerr << "[ConfigController] Error reading public config: "
                            << entry.path() << ": " << e.what() << std::endl;
                    }
                }
            }
        }

        // Log des totaux pour v�rification
        std::cout << "[ConfigController] Total configs: " << configs.size()
            << ", Total downloads: " << totalDownloads
            << ", Total likes: " << totalLikes
            << ", Total dislikes: " << totalDislikes << std::endl;

        // V�rifier s'il s'agit d'une demande de statistiques uniquement
        // (Si le payload contient seulement un uint8_t avec la valeur 1)

        // Cr�er les statistiques
        PublicConfigStats stats;
        stats.totalConfigs = static_cast<uint32_t>(configs.size());
        stats.totalDownloads = totalDownloads;
        stats.totalLikes = totalLikes;
        stats.totalDislikes = totalDislikes;
        stats.activeUsers = activeUsers.size();
        stats.lastUpdateTimestamp = static_cast<uint32_t>(std::time(nullptr));

        // Pr�parer la r�ponse avec les statistiques
        size_t dataSize = sizeof(PublicConfigStats);

        // Cr�er un buffer temporaire
        char* dataBuffer = new char[dataSize];
        memcpy(dataBuffer, &stats, dataSize);

        // Pr�parer la r�ponse finale
        ConfigResponse response;
        response.status = 0; // Success
        response.dataSize = static_cast<uint32_t>(dataSize);

        // Cr�er la r�ponse
        char* result = createSafeResponse(response, dataBuffer, dataSize);

        // Lib�rer le buffer temporaire
        delete[] dataBuffer;

        std::cout << "[ConfigController] Returning stats: configs=" << stats.totalConfigs
            << ", downloads=" << stats.totalDownloads
            << ", likes=" << stats.totalLikes << std::endl;

        return result;
    }
    catch (const std::exception& e) {
        std::cerr << "[ConfigController] Error listing public configs: " << e.what() << std::endl;

        // Cr�er une r�ponse d'erreur
        ConfigResponse response;
        response.status = 5; // Server error
        response.dataSize = 0;

        return createSafeResponse(response);
    }
}

const char* ConfigController::handleListMyPublicConfigs(const char* hwid) {
    // V�rifier l'authentification
    if (!hwid || hwid[0] == '\0') {
        ConfigResponse response;
        response.status = 3; // Access denied
        response.dataSize = 0;
        return createSafeResponse(response);
    }

    // Obtenir le nom d'utilisateur et le HWID de l'utilisateur actuel
    std::string currentUser = getUsernameFromHwid(hwid);
    std::string currentHwid = hwid;

    logMessage("[ConfigController] Listing public configs for user: " + currentUser + " (HWID: " + currentHwid + ")");

    // S'assurer que le r�pertoire des configurations publiques existe
    if (!std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR)) {
        try {
            std::filesystem::create_directories(PUBLIC_CONFIG_BASE_DIR);
            logMessage("[ConfigController] Created public configs directory: " + PUBLIC_CONFIG_BASE_DIR);
        }
        catch (const std::exception& e) {
            logMessage("[ConfigController] Failed to create public configs directory: " + std::string(e.what()));
            ConfigResponse response;
            response.status = 5; // Server error
            response.dataSize = 0;
            return createSafeResponse(response);
        }
    }

    // Collecter les configurations de l'utilisateur
    std::vector<PublicConfigInfo> userConfigs;

    if (std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR)) {
        for (const auto& entry : std::filesystem::directory_iterator(PUBLIC_CONFIG_BASE_DIR)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                try {
                    std::ifstream file(entry.path());
                    if (file.is_open()) {
                        // V�rifier que le fichier est un JSON valide
                        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                        file.seekg(0, std::ios::beg); // Revenir au d�but du fichier

                        if (content.empty() || content[0] != '{') {
                            logMessage("[ConfigController] Invalid JSON format in file: " + entry.path().string());
                            continue;
                        }

                        nlohmann::json configJson;
                        file >> configJson;

                        // V�rifier la pr�sence des champs requis
                        if (!configJson.contains("name") || !configJson.contains("description") ||
                            !configJson.contains("creator") || !configJson.contains("date") ||
                            !configJson.contains("share_code")) {
                            logMessage("[ConfigController] Missing required fields in config file: " + entry.path().string());
                            continue;
                        }

                        // V�rifier si cette config appartient � l'utilisateur actuel
                        bool isOwner = false;

                        // M�thode 1: V�rifier par real_creator (nouveau syst�me)
                        if (configJson.contains("real_creator")) {
                            std::string realCreator = configJson["real_creator"];
                            if (realCreator == currentUser) {
                                isOwner = true;
                            }
                        }

                        // M�thode 2: V�rifier par HWID (nouveau syst�me)
                        if (!isOwner && configJson.contains("hwid")) {
                            std::string configHwid = configJson["hwid"];
                            if (configHwid == currentHwid) {
                                isOwner = true;
                            }
                        }

                        // M�thode 3: V�rifier par creator (ancien syst�me, pour les configs non-anonymes)
                        if (!isOwner) {
                            std::string creator = configJson["creator"];
                            if (creator == currentUser && creator != "Anonymous") {
                                isOwner = true;
                            }
                        }

                        // Si c'est la config de l'utilisateur, l'ajouter � la liste
                        if (isOwner) {
                            PublicConfigInfo info;
                            memset(&info, 0, sizeof(info)); // Important: initialiser � z�ro

                            std::string name = configJson["name"];
                            std::string description = configJson["description"];
                            std::string creator = configJson["creator"]; // Peut �tre "Anonymous"
                            std::string date = configJson["date"];
                            std::string shareCode = configJson["share_code"];

                            strncpy(info.name, name.c_str(), sizeof(info.name) - 1);
                            info.name[sizeof(info.name) - 1] = '\0';

                            strncpy(info.description, description.c_str(), sizeof(info.description) - 1);
                            info.description[sizeof(info.description) - 1] = '\0';

                            strncpy(info.creator, creator.c_str(), sizeof(info.creator) - 1);
                            info.creator[sizeof(info.creator) - 1] = '\0';

                            strncpy(info.date, date.c_str(), sizeof(info.date) - 1);
                            info.date[sizeof(info.date) - 1] = '\0';

                            strncpy(info.share_code, shareCode.c_str(), sizeof(info.share_code) - 1);
                            info.share_code[sizeof(info.share_code) - 1] = '\0';

                            info.likes = configJson["likes"];
                            info.dislikes = configJson["dislikes"];
                            info.downloads = configJson["downloads"];

                            userConfigs.push_back(info);

                            // Log pour d�bogage
                            logMessage("[ConfigController] Found user config: " + name +
                                " (displayed as: " + creator +
                                ", share code: " + shareCode + ")");
                        }
                    }
                }
                catch (const std::exception& e) {
                    logMessage("[ConfigController] Error reading public config: " + entry.path().string() + ": " + e.what());
                }
            }
        }
    }

    // Trier par date (plus r�cent d'abord)
    std::sort(userConfigs.begin(), userConfigs.end(), [](const auto& a, const auto& b) {
        return strcmp(a.date, b.date) > 0;
        });

    // Journalisation du nombre de configurations trouv�es
    logMessage("[ConfigController] Found " + std::to_string(userConfigs.size()) +
        " public configs for user: " + currentUser);

    // Pr�parer la r�ponse: [count(uint32_t)][configInfo1][configInfo2]...
    uint32_t configsCount = static_cast<uint32_t>(userConfigs.size());
    size_t dataSize = sizeof(uint32_t) + configsCount * sizeof(PublicConfigInfo);

    // Cr�er un buffer pour les donn�es
    char* dataBuffer = new char[dataSize];
    memset(dataBuffer, 0, dataSize); // Initialiser � z�ro pour �viter des valeurs al�atoires

    // �crire le nombre de configurations
    *reinterpret_cast<uint32_t*>(dataBuffer) = configsCount;

    // �crire les informations de configuration
    if (configsCount > 0) {
        memcpy(dataBuffer + sizeof(uint32_t), userConfigs.data(), configsCount * sizeof(PublicConfigInfo));
    }

    // Journalisation de la r�ponse
    logMessage("[ConfigController] Returning " + std::to_string(configsCount) +
        " user configs, data size: " + std::to_string(dataSize) + " bytes");

    // Cr�er la r�ponse finale
    ConfigResponse response;
    response.status = 0; // Success
    response.dataSize = static_cast<uint32_t>(dataSize);

    // Utiliser createSafeResponse pour construire la r�ponse
    char* responseBuffer = createSafeResponse(response, dataBuffer, dataSize);

    // Lib�rer le buffer temporaire
    delete[] dataBuffer;

    return responseBuffer;
}

// Server-side: ConfigController.cpp
const char* ConfigController::handleRatePublicConfig(const char* shareCode,
    const void* additionalData, size_t additionalDataSize, const char* hwid) {

    // Verify authentication
    if (!hwid || hwid[0] == '\0') {
        ConfigResponse response;
        response.status = 3; // Access denied
        response.dataSize = 0;
        return createSafeResponse(response);
    }

    try {
        // Verify additional data is valid
        if (additionalData == nullptr || additionalDataSize < sizeof(bool)) {
            ConfigResponse response;
            response.status = 1; // Invalid data
            response.dataSize = 0;
            return createSafeResponse(response);
        }

        // Extract vote information
        bool isPositive = *reinterpret_cast<const bool*>(additionalData);

        // Check if config exists
        std::string configPath = PUBLIC_CONFIG_BASE_DIR + "/" + std::string(shareCode) + ".json";
        if (!std::filesystem::exists(configPath)) {
            std::cerr << "[ConfigController] Public config not found for rating: " << shareCode << std::endl;
            ConfigResponse response;
            response.status = 2; // Not found
            response.dataSize = 0;
            return createSafeResponse(response);
        }

        // Check if user has already voted for this configuration
        bool alreadyVoted = hasUserVoted(hwid, shareCode);
        bool hasLiked = hasUserLiked(hwid, shareCode);
        bool hasDisliked = hasUserDisliked(hwid, shareCode);

        // Read config file
        std::ifstream file(configPath);
        if (!file.is_open()) {
            std::cerr << "[ConfigController] Failed to open public config for rating: " << configPath << std::endl;
            ConfigResponse response;
            response.status = 5; // Server error
            response.dataSize = 0;
            return createSafeResponse(response);
        }

        nlohmann::json configJson;
        try {
            file >> configJson;
        }
        catch (const std::exception& e) {
            file.close();
            std::cerr << "[ConfigController] Error parsing config JSON for rating: " << e.what() << std::endl;
            ConfigResponse response;
            response.status = 5; // Server error
            response.dataSize = 0;
            return createSafeResponse(response);
        }
        file.close();

        // Get current counters
        int likes = configJson["likes"].get<int>();
        int dislikes = configJson["dislikes"].get<int>();

        // Logic for handling votes - key changes here!
        if (!alreadyVoted) {
            // First vote
            if (isPositive) {
                likes++;
            }
            else {
                dislikes++;
            }
            std::cout << "[ConfigController] New vote - User " << getUsernameFromHwid(hwid)
                << " " << (isPositive ? "liked" : "disliked") << " config " << shareCode << std::endl;
        }
        else if (isPositive && hasDisliked) {
            // Change from dislike to like
            likes++;
            dislikes--;
            std::cout << "[ConfigController] Changed vote - User " << getUsernameFromHwid(hwid)
                << " changed from dislike to like for config " << shareCode << std::endl;
        }
        else if (!isPositive && hasLiked) {
            // Change from like to dislike
            likes--;
            dislikes++;
            std::cout << "[ConfigController] Changed vote - User " << getUsernameFromHwid(hwid)
                << " changed from like to dislike for config " << shareCode << std::endl;
        }
        else {
            // Same vote again, ignore
            std::cout << "[ConfigController] Duplicate vote - User " << getUsernameFromHwid(hwid)
                << " attempted same " << (isPositive ? "like" : "dislike") << " again for config " << shareCode << std::endl;

            ConfigResponse response;
            response.status = 0; // Success (even though no change)
            response.dataSize = 0;
            return createSafeResponse(response);
        }

        // Update counters
        configJson["likes"] = likes;
        configJson["dislikes"] = dislikes;

        // Save changes
        std::ofstream outFile(configPath);
        if (!outFile.is_open()) {
            std::cerr << "[ConfigController] Failed to open config file for saving rating: " << configPath << std::endl;
            ConfigResponse response;
            response.status = 5; // Server error
            response.dataSize = 0;
            return createSafeResponse(response);
        }

        outFile << configJson.dump(4);
        outFile.close();

        // Save or update the user's vote

        // Create votes directory if it doesn't exist
        std::string votesDir = PUBLIC_CONFIG_BASE_DIR + "/votes";
        std::filesystem::create_directories(votesDir);

        // Save vote
        std::string voteFilename = votesDir + "/" + shareCode + "_" + hwid + ".json";
        nlohmann::json voteJson;
        voteJson["hwid"] = hwid;
        voteJson["share_code"] = shareCode;
        voteJson["is_positive"] = isPositive;
        voteJson["timestamp"] = TimeUtils::getUnixTimestamp();

        std::ofstream voteFile(voteFilename);
        if (voteFile.is_open()) {
            voteFile << voteJson.dump(4);
            voteFile.close();
        }

        // Update local vote status
        userVotes[hwid][shareCode] = isPositive;

        // Return success
        ConfigResponse response;
        response.status = 0; // Success
        response.dataSize = 0;
        return createSafeResponse(response);
    }
    catch (const std::exception& e) {
        std::cerr << "[ConfigController] Error rating config: " << e.what() << std::endl;
        ConfigResponse response;
        response.status = 5; // Server error
        response.dataSize = 0;
        return createSafeResponse(response);
    }
}


// Fonction pour incr�menter le compteur de t�l�chargements
bool ConfigController::incrementDownloadCount(const char* shareCode) {
    try {
        std::string configPath = PUBLIC_CONFIG_BASE_DIR + "/" + shareCode + ".json";

        if (!std::filesystem::exists(configPath)) {
            return false;
        }

        std::ifstream file(configPath);
        if (!file.is_open()) {
            return false;
        }

        nlohmann::json configJson;
        file >> configJson;
        file.close();

        // Incr�menter le compteur
        configJson["downloads"] = configJson["downloads"].get<int>() + 1;

        // Enregistrer les changements
        std::ofstream outFile(configPath);
        outFile << configJson.dump(4);

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[ConfigController] Error incrementing download count: " << e.what() << std::endl;
        return false;
    }
}

const char* ConfigController::handlePreviewPublicConfig(const char* shareCode) {
    // Note: Preview is now available without authentication

    try {
        // Charger la configuration publique (r�utiliser la m�thode existante)
        std::string name, description, creator, date;
        std::vector<uint8_t> data;

        if (!loadPublicConfig(shareCode, name, description, creator, date, data)) {
            logMessage("[ConfigController] Public config not found for preview: " + std::string(shareCode));
            ConfigResponse response;
            response.status = 2; // Not found
            response.dataSize = 0;
            return createSafeResponse(response);
        }

        // NE PAS incr�menter le compteur de t�l�chargements pour la preview

        // Format de retour identique � DOWNLOAD mais sans incr�menter les stats:
        // [name_len(uint32)][name][desc_len(uint32)][description][creator_len(uint32)][creator][date_len(uint32)][date][data]

        uint32_t nameLen = static_cast<uint32_t>(name.size());
        uint32_t descLen = static_cast<uint32_t>(description.size());
        uint32_t creatorLen = static_cast<uint32_t>(creator.size());
        uint32_t dateLen = static_cast<uint32_t>(date.size());

        size_t totalSize = 4 * sizeof(uint32_t) + nameLen + descLen + creatorLen + dateLen + data.size();

        char* responseData = new char[totalSize];
        char* ptr = responseData;

        // �crire le nom
        memcpy(ptr, &nameLen, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, name.c_str(), nameLen);
        ptr += nameLen;

        // �crire la description
        memcpy(ptr, &descLen, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, description.c_str(), descLen);
        ptr += descLen;

        // �crire le cr�ateur
        memcpy(ptr, &creatorLen, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, creator.c_str(), creatorLen);
        ptr += creatorLen;

        // �crire la date
        memcpy(ptr, &dateLen, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, date.c_str(), dateLen);
        ptr += dateLen;

        // �crire les donn�es
        memcpy(ptr, data.data(), data.size());

        ConfigResponse response;
        response.status = 0; // Success
        response.dataSize = static_cast<uint32_t>(totalSize);

        size_t fullResponseSize = sizeof(ConfigResponse) + totalSize;
        char* result = new char[fullResponseSize];
        memcpy(result, &response, sizeof(ConfigResponse));
        memcpy(result + sizeof(ConfigResponse), responseData, totalSize);

        delete[] responseData;

        logMessage("[ConfigController] Config previewed (no download count increment): " + name);

        return result;

    }
    catch (const std::exception& e) {
        logMessage("[ConfigController] Error previewing config: " + std::string(e.what()));
        ConfigResponse response;
        response.status = 5; // Server error
        response.dataSize = 0;
        return createSafeResponse(response);
    }
}

const char* ConfigController::handleDownloadPublicConfigToServer(const char* shareCode, const char* hwid) {
    // V�rifier l'authentification
    if (!hwid || hwid[0] == '\0') {
        ConfigResponse response;
        response.status = 3; // Access denied
        response.dataSize = 0;
        return createSafeResponse(response);
    }

    try {
        // Charger la configuration publique
        std::string name, description, creator, date;
        std::vector<uint8_t> data;

        if (!loadPublicConfig(shareCode, name, description, creator, date, data)) {
            logMessage("[ConfigController] Public config not found: " + std::string(shareCode));
            ConfigResponse response;
            response.status = 2; // Not found
            response.dataSize = 0;
            return createSafeResponse(response);
        }

        // Obtenir le nom d'utilisateur du t�l�chargeur
        std::string downloaderUsername = getUsernameFromHwid(hwid);

        // NOUVELLE VERIFICATION : V�rifier si l'utilisateur a d�j� t�l�charg� cette config
        if (hasUserAlreadyDownloadedConfig(hwid, shareCode)) {
            logMessage("[ConfigController] User " + downloaderUsername +
                " already has downloaded config with share code: " + std::string(shareCode));

            ConfigResponse response;
            response.status = 6; // Already exists (nouveau code d'erreur)
            response.dataSize = 0;
            return createSafeResponse(response);
        }

        // Cr�er un nom de fichier simplifi�
        std::string configName;

        // Format simplifi� : "ConfigName by Creator" ou juste "ConfigName" si Anonymous
        if (creator == "Anonymous") {
            configName = name;
        }
        else {
            configName = name + " by " + creator;
        }

        // Limiter la longueur du nom � 31 caract�res (pour respecter la limite de 32 avec le \0)
        if (configName.length() > 31) {
            configName = configName.substr(0, 28) + "...";
        }

        // V�rifier si une config avec ce nom existe d�j� pour cet utilisateur
        std::string existingDesc;
        std::vector<uint8_t> existingData;
        int suffix = 1;
        std::string finalConfigName = configName;

        while (loadUserConfig(hwid, finalConfigName.c_str(), existingDesc, existingData)) {
            // Une config avec ce nom existe d�j�, ajouter un suffixe
            finalConfigName = configName + " (" + std::to_string(suffix) + ")";
            suffix++;

            // Limiter encore la longueur si n�cessaire
            if (finalConfigName.length() > 31) {
                std::string baseConfigName = configName.substr(0, 25 - std::to_string(suffix).length()) + "...";
                finalConfigName = baseConfigName + " (" + std::to_string(suffix) + ")";
            }
        }

        // Utiliser la description originale sans ajouts suppl�mentaires
        std::string finalDescription = description;

        // Sauvegarder la configuration dans les configs priv�es de l'utilisateur
        if (saveUserConfig(hwid, finalConfigName.c_str(), finalDescription.c_str(),
            reinterpret_cast<const char*>(data.data()), data.size())) {

            // IMPORTANT : Enregistrer le t�l�chargement pour �viter les doublons futurs
            recordUserDownload(hwid, shareCode, finalConfigName);

            // Incr�menter le compteur de t�l�chargements
            incrementDownloadCount(shareCode);

            logMessage("[ConfigController] Public config downloaded and saved: " + finalConfigName +
                " for user " + downloaderUsername + " (share code: " + std::string(shareCode) + ")");

            // Pr�parer la r�ponse de succ�s avec le nom de la config sauvegard�e
            std::string successMessage = "Config saved as: " + finalConfigName;

            size_t messageSize = successMessage.size();
            char* dataBuffer = new char[messageSize];
            memcpy(dataBuffer, successMessage.c_str(), messageSize);

            ConfigResponse response;
            response.status = 0; // Success
            response.dataSize = static_cast<uint32_t>(messageSize);

            char* result = createSafeResponse(response, dataBuffer, messageSize);
            delete[] dataBuffer;

            return result;
        }
        else {
            logMessage("[ConfigController] Failed to save downloaded config for user " + downloaderUsername);
            ConfigResponse response;
            response.status = 5; // Server error
            response.dataSize = 0;
            return createSafeResponse(response);
        }

    }
    catch (const std::exception& e) {
        logMessage("[ConfigController] Error downloading config: " + std::string(e.what()));
        ConfigResponse response;
        response.status = 5; // Server error
        response.dataSize = 0;
        return createSafeResponse(response);
    }
}

bool ConfigController::hasUserAlreadyDownloadedConfig(const char* hwid, const char* shareCode) {
    try {
        // Cr�er le r�pertoire des t�l�chargements s'il n'existe pas
        std::string downloadsDir = CONFIG_BASE_DIR + "/downloads";
        if (!std::filesystem::exists(downloadsDir)) {
            return false; // Pas de t�l�chargements enregistr�s
        }

        // V�rifier si le fichier de t�l�chargement existe
        std::string downloadFile = downloadsDir + "/" + std::string(hwid) + "_" + std::string(shareCode) + ".json";
        return std::filesystem::exists(downloadFile);
    }
    catch (const std::exception& e) {
        logMessage("[ConfigController] Error checking download record: " + std::string(e.what()));
        return false;
    }
}

void ConfigController::recordUserDownload(const char* hwid, const char* shareCode, const std::string& savedConfigName) {
    try {
        // Cr�er le r�pertoire des t�l�chargements s'il n'existe pas
        std::string downloadsDir = CONFIG_BASE_DIR + "/downloads";
        std::filesystem::create_directories(downloadsDir);

        // Cr�er l'enregistrement du t�l�chargement
        nlohmann::json downloadRecord;
        downloadRecord["hwid"] = hwid;
        downloadRecord["share_code"] = shareCode;
        downloadRecord["saved_config_name"] = savedConfigName;
        downloadRecord["download_timestamp"] = TimeUtils::getUnixTimestamp();
        downloadRecord["username"] = getUsernameFromHwid(hwid);

        // Sauvegarder l'enregistrement
        std::string downloadFile = downloadsDir + "/" + std::string(hwid) + "_" + std::string(shareCode) + ".json";
        std::ofstream file(downloadFile);
        if (file.is_open()) {
            file << downloadRecord.dump(4);
            file.close();
            logMessage("[ConfigController] Download recorded: " + downloadFile);
        }
        else {
            logMessage("[ConfigController] Failed to record download: " + downloadFile);
        }
    }
    catch (const std::exception& e) {
        logMessage("[ConfigController] Error recording download: " + std::string(e.what()));
    }
}

void ConfigController::removeUserDownloadRecord(const char* hwid, const char* shareCode) {
    try {
        std::string downloadsDir = CONFIG_BASE_DIR + "/downloads";
        std::string downloadFile = downloadsDir + "/" + std::string(hwid) + "_" + std::string(shareCode) + ".json";

        if (std::filesystem::exists(downloadFile)) {
            std::filesystem::remove(downloadFile);
            logMessage("[ConfigController] Download record removed: " + downloadFile);
        }
    }
    catch (const std::exception& e) {
        logMessage("[ConfigController] Error removing download record: " + std::string(e.what()));
    }
}
// Fichier: Controller/impl/ConfigController.cpp (extensions)

// Version simplifi�e de handleUnpublishConfig - focus sur real_creator pour les configs anonymes

const char* ConfigController::handleUnpublishConfig(const char* shareCode, const char* hwid) {
    // V�rifier l'authentification
    if (!hwid || hwid[0] == '\0') {
        logMessage("[ConfigController] ERROR: No hwid provided");

        ConfigResponse response;
        response.status = 3; // Access denied
        response.dataSize = 0;
        return createSafeResponse(response);
    }

    logMessage("[ConfigController] Unpublish request for share code: " + std::string(shareCode));
    logMessage("[ConfigController] User HWID: " + std::string(hwid));

    // V�rifier si la configuration existe
    std::string configPath = PUBLIC_CONFIG_BASE_DIR + "/" + std::string(shareCode) + ".json";
    logMessage("[ConfigController] Looking for config file: " + configPath);

    if (!std::filesystem::exists(configPath)) {
        logMessage("[ConfigController] Config file not found: " + configPath);

        ConfigResponse response;
        response.status = 2; // Config not found
        response.dataSize = 0;
        return createSafeResponse(response);
    }

    // Lire le fichier de configuration
    std::ifstream file(configPath);
    if (!file.is_open()) {
        logMessage("[ConfigController] Failed to open config file: " + configPath);

        ConfigResponse response;
        response.status = 5; // Server error
        response.dataSize = 0;
        return createSafeResponse(response);
    }

    nlohmann::json configJson;
    try {
        file >> configJson;
        file.close();
        logMessage("[ConfigController] Config JSON parsed successfully");
    }
    catch (const std::exception& e) {
        file.close();
        logMessage("[ConfigController] Failed to parse config JSON: " + std::string(e.what()));

        ConfigResponse response;
        response.status = 5; // Server error
        response.dataSize = 0;
        return createSafeResponse(response);
    }

    // Obtenir le nom d'utilisateur actuel
    std::string currentUser = getUsernameFromHwid(hwid);

    // Extraire le vrai cr�ateur de la config
    std::string realCreator = "";
    if (configJson.contains("real_creator")) {
        realCreator = configJson["real_creator"].get<std::string>();
    }

    logMessage("[ConfigController] Current user: '" + currentUser + "'");
    logMessage("[ConfigController] Config real_creator: '" + realCreator + "'");

    // V�rifier les permissions
    bool isAdmin = isUserAdmin(hwid);
    bool isRealCreator = (currentUser == realCreator);

    logMessage("[ConfigController] Permission analysis:");
    logMessage("[ConfigController] - Is admin: " + std::string(isAdmin ? "YES" : "NO"));
    logMessage("[ConfigController] - Is real creator: " + std::string(isRealCreator ? "YES" : "NO"));

    // D�cision finale : admin OU vrai cr�ateur
    bool canDelete = isAdmin || isRealCreator;

    logMessage("[ConfigController] Final decision: Can delete = " + std::string(canDelete ? "YES" : "NO"));

    if (!canDelete) {
        logMessage("[ConfigController] ACCESS DENIED - User '" + currentUser +
            "' is not the real creator ('" + realCreator + "') and not admin");

        ConfigResponse response;
        response.status = 3; // Access denied
        response.dataSize = 0;
        return createSafeResponse(response);
    }

    // Supprimer le fichier
    try {
        if (std::filesystem::remove(configPath)) {
            logMessage("[ConfigController] Config unpublished successfully: " + std::string(shareCode) +
                " by " + currentUser + " (real creator match)");

            ConfigResponse response;
            response.status = 0; // Success
            response.dataSize = 0;
            return createSafeResponse(response);
        }
        else {
            logMessage("[ConfigController] Failed to delete config file: " + configPath);

            ConfigResponse response;
            response.status = 5; // Server error
            response.dataSize = 0;
            return createSafeResponse(response);
        }
    }
    catch (const std::exception& e) {
        logMessage("[ConfigController] Exception during file deletion: " + std::string(e.what()));

        ConfigResponse response;
        response.status = 5; // Server error
        response.dataSize = 0;
        return createSafeResponse(response);
    }
}

// Mettre � jour une configuration publique
const char* ConfigController::handleUpdatePublicConfig(const ConfigRequest& request,
    const void* additionalData, size_t additionalDataSize, const char* hwid) {

    // V�rifier l'authentification
    if (!hwid || hwid[0] == '\0') {
        return createErrorResponse("Authentication required");
    }

    // V�rifier que les donn�es additionnelles sont suffisantes
    if (additionalData == nullptr || additionalDataSize < sizeof(uint32_t)) {
        ConfigResponse response;
        response.status = 1; // Invalid data
#ifdef _WIN32
    #ifdef _WIN32
    return _strdup(reinterpret_cast<const char*>(&response));
#else
    return strdup(reinterpret_cast<const char*>(&response));
#endif
#else
        return strdup(reinterpret_cast<const char*>(&response));
#endif
    }

    // Extraire la description et les donn�es
    uint32_t descSize = *reinterpret_cast<const uint32_t*>(additionalData);
    if (sizeof(uint32_t) + descSize > additionalDataSize) {
        ConfigResponse response;
        response.status = 1; // Invalid data
#ifdef _WIN32
    #ifdef _WIN32
    return _strdup(reinterpret_cast<const char*>(&response));
#else
    return strdup(reinterpret_cast<const char*>(&response));
#endif
#else
        return strdup(reinterpret_cast<const char*>(&response));
#endif
    }

    std::string description(
        reinterpret_cast<const char*>(additionalData) + sizeof(uint32_t),
        descSize
    );

    size_t dataSize = additionalDataSize - sizeof(uint32_t) - descSize;
    const void* data = reinterpret_cast<const char*>(additionalData) + sizeof(uint32_t) + descSize;

    // V�rifier si la configuration existe
    std::string shareCode = request.configName;
    std::string configPath = PUBLIC_CONFIG_BASE_DIR + "/" + shareCode + ".json";

    if (!std::filesystem::exists(configPath)) {
        ConfigResponse response;
        response.status = 2; // Config not found
#ifdef _WIN32
    #ifdef _WIN32
    return _strdup(reinterpret_cast<const char*>(&response));
#else
    return strdup(reinterpret_cast<const char*>(&response));
#endif
#else
        return strdup(reinterpret_cast<const char*>(&response));
#endif
    }

    // V�rifier si l'utilisateur est le propri�taire
    std::ifstream file(configPath);
    if (!file.is_open()) {
        ConfigResponse response;
        response.status = 5; // Server error
#ifdef _WIN32
    #ifdef _WIN32
    return _strdup(reinterpret_cast<const char*>(&response));
#else
    return strdup(reinterpret_cast<const char*>(&response));
#endif
#else
        return strdup(reinterpret_cast<const char*>(&response));
#endif
    }

    nlohmann::json configJson;
    file >> configJson;
    file.close();

    std::string creator = configJson["creator"];

    // V�rifier si l'utilisateur peut modifier cette configuration
    bool isAdmin = isUserAdmin(hwid);
    bool isOwner = getUsernameFromHwid(hwid) == creator;

    if (!isOwner && !isAdmin) {
        ConfigResponse response;
        response.status = 3; // Access denied
#ifdef _WIN32
    #ifdef _WIN32
    return _strdup(reinterpret_cast<const char*>(&response));
#else
    return strdup(reinterpret_cast<const char*>(&response));
#endif
#else
        return strdup(reinterpret_cast<const char*>(&response));
#endif
    }

    // Mettre � jour la configuration
    configJson["description"] = description;

    // Les donn�es restent au format binaire
    std::vector<uint8_t> newData(reinterpret_cast<const uint8_t*>(data),
        reinterpret_cast<const uint8_t*>(data) + dataSize);
    configJson["data"] = newData;

    // Mettre � jour la date de modification
    configJson["date"] = TimeUtils::formatTime(std::time(nullptr));

    // Sauvegarder le fichier mis � jour
    std::ofstream outFile(configPath);
    if (!outFile.is_open()) {
        ConfigResponse response;
        response.status = 5; // Server error
#ifdef _WIN32
    #ifdef _WIN32
    return _strdup(reinterpret_cast<const char*>(&response));
#else
    return strdup(reinterpret_cast<const char*>(&response));
#endif
#else
        return strdup(reinterpret_cast<const char*>(&response));
#endif
    }

    outFile << configJson.dump(4);

    // Pr�parer la r�ponse
    ConfigResponse response;
    response.status = 0; // Success

    // Log de l'op�ration
    logMessage("[ConfigController] Config updated: " + shareCode +
        " by " + getUsernameFromHwid(hwid));

#ifdef _WIN32
    return _strdup(reinterpret_cast<const char*>(&response));
#else
    return strdup(reinterpret_cast<const char*>(&response));
#endif
}

// Lister les configurations avec pagination
const char* ConfigController::handleListPublicConfigsWithPagination(const void* additionalData,
    size_t additionalDataSize) {

    // Note: Public config listing is now available without authentication

    // Extraire les param�tres de pagination
    int page = 0;
    int pageSize = 15; // Toujours utiliser 15 comme taille de page, ind�pendamment de la requ�te
    std::string searchQuery;

    if (additionalData && additionalDataSize >= sizeof(int32_t) * 2) {
        const PaginationRequest* request = reinterpret_cast<const PaginationRequest*>(additionalData);
        page = request->page;
        // pageSize toujours 15, ignorant request->pageSize

        if (request->searchQuery[0] != '\0') {
            searchQuery = request->searchQuery;
        }
    }

    // S'assurer que les valeurs sont valides
    if (page < 0) page = 0;

    // Collecter toutes les configurations publiques
    std::vector<PublicConfigInfo> allConfigs;

    if (std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR)) {
        for (const auto& entry : std::filesystem::directory_iterator(PUBLIC_CONFIG_BASE_DIR)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                try {
                    std::ifstream file(entry.path());
                    if (file.is_open()) {
                        nlohmann::json configJson;
                        file >> configJson;

                        PublicConfigInfo info;
                        // Initialiser � z�ro pour s�curit�
                        memset(&info, 0, sizeof(PublicConfigInfo));

                        std::string name = configJson["name"];
                        std::string description = configJson["description"];
                        std::string creator = configJson["creator"];
                        std::string date = configJson["date"];
                        std::string shareCode = configJson["share_code"];

                        strncpy(info.name, name.c_str(), sizeof(info.name) - 1);
                        strncpy(info.description, description.c_str(), sizeof(info.description) - 1);
                        strncpy(info.creator, creator.c_str(), sizeof(info.creator) - 1);
                        strncpy(info.date, date.c_str(), sizeof(info.date) - 1);
                        strncpy(info.share_code, shareCode.c_str(), sizeof(info.share_code) - 1);

                        info.likes = configJson["likes"];
                        info.dislikes = configJson["dislikes"];
                        info.downloads = configJson["downloads"];

                        // Filtrer selon la recherche si n�cessaire
                        if (!searchQuery.empty()) {
                            // Convertir en minuscules pour la comparaison
                            std::string lowerName = name;
                            std::string lowerDesc = description;
                            std::string lowerCreator = creator;
                            std::string lowerQuery = searchQuery;

                            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                            std::transform(lowerDesc.begin(), lowerDesc.end(), lowerDesc.begin(), ::tolower);
                            std::transform(lowerCreator.begin(), lowerCreator.end(), lowerCreator.begin(), ::tolower);
                            std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);

                            // V�rifier si la requ�te correspond � un des champs
                            if (lowerName.find(lowerQuery) == std::string::npos &&
                                lowerDesc.find(lowerQuery) == std::string::npos &&
                                lowerCreator.find(lowerQuery) == std::string::npos) {
                                continue; // Ne pas ajouter cette config
                            }
                        }

                        allConfigs.push_back(info);
                    }
                }
                catch (const std::exception& e) {
                    logMessage("[ConfigController] Error reading public config: " + entry.path().string() + ": " + e.what());
                }
            }
        }
    }

    // Trier par date (plus r�cent d'abord)
    std::sort(allConfigs.begin(), allConfigs.end(), [](const auto& a, const auto& b) {
        return strcmp(a.date, b.date) > 0;
        });

    // Calculer le nombre total de configs
    uint32_t totalCount = static_cast<uint32_t>(allConfigs.size());

    // Calculer les indices pour la pagination
    int startIndex = page * pageSize;
    int endIndex = std::min(startIndex + pageSize, static_cast<int>(allConfigs.size()));

    // V�rifier si l'indice de d�part est valide
    if (startIndex >= static_cast<int>(allConfigs.size())) {
        startIndex = 0;
        endIndex = std::min(pageSize, static_cast<int>(allConfigs.size()));
    }

    // Nombre de configs pour cette page
    uint32_t configsCount = static_cast<uint32_t>(endIndex - startIndex);

    // Journal de diagnostic
    std::cout << "[ConfigController] Pagination: page=" << page
        << ", pageSize=" << pageSize
        << ", total=" << totalCount
        << ", returning=" << configsCount << " configs" << std::endl;

    // Pr�parer la r�ponse: [count(uint32_t)][totalCount(uint32_t)][configInfo1][configInfo2]...
    size_t dataSize = 2 * sizeof(uint32_t) + configsCount * sizeof(PublicConfigInfo);

    // Cr�er un buffer pour les donn�es
    char* dataBuffer = new char[dataSize];

    // Mettre le nombre de configurations et le nombre total
    *reinterpret_cast<uint32_t*>(dataBuffer) = configsCount;
    *reinterpret_cast<uint32_t*>(dataBuffer + sizeof(uint32_t)) = totalCount;

    // Copier les configurations
    if (configsCount > 0) {
        char* configPtr = dataBuffer + 2 * sizeof(uint32_t);
        for (int i = startIndex; i < endIndex; i++) {
            memcpy(configPtr, &allConfigs[i], sizeof(PublicConfigInfo));
            configPtr += sizeof(PublicConfigInfo);
        }
    }

    // Cr�er la r�ponse
    ConfigResponse response;
    response.status = 0; // Success
    response.dataSize = static_cast<uint32_t>(dataSize);

    std::cout << "[ConfigController] LIST_PUBLIC_PAGINATED: Preparing response with dataSize: "
        << dataSize << " bytes" << std::endl;

    // Utiliser la fonction utilitaire pour cr�er la r�ponse
    char* result = createSafeResponse(response, dataBuffer, dataSize);

    // Lib�rer le buffer temporaire
    delete[] dataBuffer;

    return result;
}

// V�rifier les mises � jour des configurations
const char* ConfigController::handleCheckForConfigUpdates() {
    // Note: Config updates check is now available without authentication

    // Trouver la configuration la plus r�cente
    uint32_t latestTimestamp = 0;

    if (std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR)) {
        for (const auto& entry : std::filesystem::directory_iterator(PUBLIC_CONFIG_BASE_DIR)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                try {
                    auto lastWriteTime = std::filesystem::last_write_time(entry.path());
                    auto epochTime = lastWriteTime.time_since_epoch().count();
                    // Conversion de l'horodatage du filesystem en epoch seconds
                    uint32_t fileTimestamp = static_cast<uint32_t>(epochTime / 10000000);
                    if (fileTimestamp > latestTimestamp) {
                        latestTimestamp = fileTimestamp;
                    }
                }
                catch (const std::exception& e) {
                    logMessage("[ConfigController] Error checking file timestamp: " + entry.path().string() + ": " + e.what());
                }
            }
        }
    }

    // Allouer la m�moire pour la r�ponse
    char* response = new char[sizeof(uint32_t)];
    *reinterpret_cast<uint32_t*>(response) = latestTimestamp;

    return response;
}

// Obtenir des statistiques sur les configurations publiques
const char* ConfigController::handleGetPublicConfigStats() {
    // Note: Public config stats are now available without authentication

    PublicConfigStats stats = { 0 };

    // Parcourir toutes les configurations pour collecter les statistiques
    if (std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR)) {
        for (const auto& entry : std::filesystem::directory_iterator(PUBLIC_CONFIG_BASE_DIR)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                try {
                    std::ifstream file(entry.path());
                    if (file.is_open()) {
                        nlohmann::json configJson;
                        file >> configJson;

                        // Incr�menter le compteur de configurations
                        stats.totalConfigs++;

                        // Ajouter aux statistiques
                        stats.totalDownloads += configJson["downloads"].get<uint32_t>();
                        stats.totalLikes += configJson["likes"].get<uint32_t>();
                        stats.totalDislikes += configJson["dislikes"].get<uint32_t>();

                        // Collecter les cr�ateurs uniques
                        std::string creator = configJson["creator"];
                        activeUsers.insert(creator);
                    }
                }
                catch (const std::exception& e) {
                    logMessage("[ConfigController] Error reading public config for stats: " + entry.path().string() + ": " + e.what());
                }
            }
        }
    }

    // Nombre d'utilisateurs actifs
    stats.activeUsers = static_cast<uint32_t>(activeUsers.size());

    // Timestamp de la mise � jour
    stats.lastUpdateTimestamp = static_cast<uint32_t>(std::time(nullptr));

    // Allouer la m�moire pour la r�ponse
    char* response = new char[sizeof(PublicConfigStats)];
    memcpy(response, &stats, sizeof(PublicConfigStats));

    return response;
}

// Rechercher des configurations publiques
const char* ConfigController::handleSearchPublicConfigs(const void* additionalData,
    size_t additionalDataSize) {

    // Note: Public config search is now available without authentication

    // Extraire les param�tres de recherche
    std::string query;
    int maxResults = 10;

    if (additionalData && additionalDataSize >= sizeof(SearchRequest)) {
        const SearchRequest* request = reinterpret_cast<const SearchRequest*>(additionalData);
        query = request->query;
        maxResults = request->maxResults;
    }

    // S'assurer que les valeurs sont valides
    if (maxResults <= 0) maxResults = 10;
    if (maxResults > 100) maxResults = 100; // Limiter le nombre de r�sultats

    // Collecter les configurations correspondant � la recherche
    std::vector<PublicConfigInfo> results;

    if (std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR) && !query.empty()) {
        // Convertir la requ�te en minuscules pour la comparaison insensible � la casse
        std::string lowerQuery = query;
        std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);

        for (const auto& entry : std::filesystem::directory_iterator(PUBLIC_CONFIG_BASE_DIR)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                try {
                    std::ifstream file(entry.path());
                    if (file.is_open()) {
                        nlohmann::json configJson;
                        file >> configJson;

                        std::string name = configJson["name"];
                        std::string description = configJson["description"];
                        std::string creator = configJson["creator"];

                        // Convertir en minuscules pour la comparaison
                        std::string lowerName = name;
                        std::string lowerDesc = description;
                        std::string lowerCreator = creator;

                        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                        std::transform(lowerDesc.begin(), lowerDesc.end(), lowerDesc.begin(), ::tolower);
                        std::transform(lowerCreator.begin(), lowerCreator.end(), lowerCreator.begin(), ::tolower);

                        // V�rifier si la requ�te correspond � un des champs
                        if (lowerName.find(lowerQuery) != std::string::npos ||
                            lowerDesc.find(lowerQuery) != std::string::npos ||
                            lowerCreator.find(lowerQuery) != std::string::npos) {

                            PublicConfigInfo info;
                            std::string date = configJson["date"];
                            std::string shareCode = configJson["share_code"];

                            strncpy(info.name, name.c_str(), sizeof(info.name) - 1);
                            strncpy(info.description, description.c_str(), sizeof(info.description) - 1);
                            strncpy(info.creator, creator.c_str(), sizeof(info.creator) - 1);
                            strncpy(info.date, date.c_str(), sizeof(info.date) - 1);
                            strncpy(info.share_code, shareCode.c_str(), sizeof(info.share_code) - 1);

                            info.likes = configJson["likes"];
                            info.dislikes = configJson["dislikes"];
                            info.downloads = configJson["downloads"];

                            results.push_back(info);

                            // Limiter le nombre de r�sultats
                            if (results.size() >= static_cast<size_t>(maxResults)) {
                                break;
                            }
                        }
                    }
                }
                catch (const std::exception& e) {
                    logMessage("[ConfigController] Error reading public config for search: " + entry.path().string() + ": " + e.what());
                }
            }
        }
    }

    // Pr�parer la r�ponse: [count(uint32_t)][configInfo1][configInfo2]...
    uint32_t configsCount = static_cast<uint32_t>(results.size());
    size_t responseSize = sizeof(uint32_t) + configsCount * sizeof(PublicConfigInfo);
    char* response = new char[responseSize];

    // �crire le nombre de configurations
    *reinterpret_cast<uint32_t*>(response) = configsCount;

    // �crire les informations de configuration
    if (configsCount > 0) {
        memcpy(response + sizeof(uint32_t), results.data(), configsCount * sizeof(PublicConfigInfo));
    }

    return response;
}

// Obtenir les configurations les plus populaires
const char* ConfigController::handleGetMostPopularConfigs(const void* additionalData,
    size_t additionalDataSize) {

    // Note: Popular configs are now available without authentication

    // Extraire le nombre de configurations demand�es
    int count = 5; // Valeur par d�faut

    if (additionalData && additionalDataSize >= sizeof(int32_t)) {
        count = *reinterpret_cast<const int32_t*>(additionalData);
    }

    // S'assurer que la valeur est valide
    if (count <= 0) count = 5;
    if (count > 15) count = 15; // Limiter le nombre de r�sultats

    // Collecter toutes les configurations
    std::vector<PublicConfigInfo> allConfigs;

    if (std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR)) {
        for (const auto& entry : std::filesystem::directory_iterator(PUBLIC_CONFIG_BASE_DIR)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                try {
                    std::ifstream file(entry.path());
                    if (file.is_open()) {
                        nlohmann::json configJson;
                        file >> configJson;

                        PublicConfigInfo info;
                        memset(&info, 0, sizeof(info)); // Important: initialize to zero

                        std::string name = configJson["name"];
                        std::string description = configJson["description"];
                        std::string creator = configJson["creator"];
                        std::string date = configJson["date"];
                        std::string shareCode = configJson["share_code"];

                        strncpy(info.name, name.c_str(), sizeof(info.name) - 1);
                        strncpy(info.description, description.c_str(), sizeof(info.description) - 1);
                        strncpy(info.creator, creator.c_str(), sizeof(info.creator) - 1);
                        strncpy(info.date, date.c_str(), sizeof(info.date) - 1);
                        strncpy(info.share_code, shareCode.c_str(), sizeof(info.share_code) - 1);

                        info.likes = configJson["likes"];
                        info.dislikes = configJson["dislikes"];
                        info.downloads = configJson["downloads"];

                        allConfigs.push_back(info);
                    }
                }
                catch (const std::exception& e) {
                    logMessage("[ConfigController] Error reading public config: " + entry.path().string() + ": " + e.what());
                }
            }
        }
    }

    // Trier par popularit� (likes - dislikes)
    std::sort(allConfigs.begin(), allConfigs.end(), [](const auto& a, const auto& b) {
        int scoreA = a.likes - a.dislikes;
        int scoreB = b.likes - b.dislikes;
        return scoreA > scoreB;  // Ordre d�croissant
        });

    // Limiter au nombre demand�
    if (allConfigs.size() > static_cast<size_t>(count)) {
        allConfigs.resize(count);
    }

    // Pr�parer la r�ponse
    uint32_t configsCount = static_cast<uint32_t>(allConfigs.size());

    // Calculer la taille des donn�es
    size_t dataSize = sizeof(uint32_t) + configsCount * sizeof(PublicConfigInfo);

    // Cr�er un buffer pour les donn�es
    char* dataBuffer = new char[dataSize];

    // �crire le nombre de configurations
    *reinterpret_cast<uint32_t*>(dataBuffer) = configsCount;

    // �crire les configurations
    if (configsCount > 0) {
        memcpy(dataBuffer + sizeof(uint32_t), allConfigs.data(), configsCount * sizeof(PublicConfigInfo));
    }

    // Pr�parer la r�ponse
    ConfigResponse response;
    response.status = 0; // Success
    response.dataSize = static_cast<uint32_t>(dataSize);

    // Cr�er la r�ponse avec les donn�es
    char* result = createSafeResponse(response, dataBuffer, dataSize);

    // Lib�rer le buffer temporaire
    delete[] dataBuffer;

    return result;
}

// Obtenir les configurations r�centes
const char* ConfigController::handleGetRecentConfigs(const void* additionalData,
    size_t additionalDataSize) {

    // Note: Recent configs are now available without authentication

    // Extraire le nombre de configurations demand�es
    int count = 5; // Valeur par d�faut

    if (additionalData && additionalDataSize >= sizeof(int32_t)) {
        count = *reinterpret_cast<const int32_t*>(additionalData);
    }

    // S'assurer que la valeur est valide
    if (count <= 0) count = 5;
    if (count > 15) count = 15; // Limiter le nombre de r�sultats

    // Collecter toutes les configurations
    std::vector<PublicConfigInfo> allConfigs;

    if (std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR)) {
        for (const auto& entry : std::filesystem::directory_iterator(PUBLIC_CONFIG_BASE_DIR)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                try {
                    std::ifstream file(entry.path());
                    if (file.is_open()) {
                        nlohmann::json configJson;
                        file >> configJson;

                        PublicConfigInfo info;
                        memset(&info, 0, sizeof(info)); // Important: initialize to zero

                        std::string name = configJson["name"];
                        std::string description = configJson["description"];
                        std::string creator = configJson["creator"];
                        std::string date = configJson["date"];
                        std::string shareCode = configJson["share_code"];

                        strncpy(info.name, name.c_str(), sizeof(info.name) - 1);
                        strncpy(info.description, description.c_str(), sizeof(info.description) - 1);
                        strncpy(info.creator, creator.c_str(), sizeof(info.creator) - 1);
                        strncpy(info.date, date.c_str(), sizeof(info.date) - 1);
                        strncpy(info.share_code, shareCode.c_str(), sizeof(info.share_code) - 1);

                        info.likes = configJson["likes"];
                        info.dislikes = configJson["dislikes"];
                        info.downloads = configJson["downloads"];

                        allConfigs.push_back(info);
                    }
                }
                catch (const std::exception& e) {
                    logMessage("[ConfigController] Error reading public config: " + entry.path().string() + ": " + e.what());
                }
            }
        }
    }

    // Trier par date (plus r�cent d'abord)
    std::sort(allConfigs.begin(), allConfigs.end(), [](const auto& a, const auto& b) {
        return strcmp(a.date, b.date) > 0;
        });

    // Limiter au nombre demand�
    if (allConfigs.size() > static_cast<size_t>(count)) {
        allConfigs.resize(count);
    }

    // Pr�parer la r�ponse
    uint32_t configsCount = static_cast<uint32_t>(allConfigs.size());

    // Calculer la taille des donn�es
    size_t dataSize = sizeof(uint32_t) + configsCount * sizeof(PublicConfigInfo);

    // Cr�er un buffer pour les donn�es
    char* dataBuffer = new char[dataSize];

    // �crire le nombre de configurations
    *reinterpret_cast<uint32_t*>(dataBuffer) = configsCount;

    // �crire les configurations
    if (configsCount > 0) {
        memcpy(dataBuffer + sizeof(uint32_t), allConfigs.data(), configsCount * sizeof(PublicConfigInfo));
    }

    // Pr�parer la r�ponse
    ConfigResponse response;
    response.status = 0; // Success
    response.dataSize = static_cast<uint32_t>(dataSize);

    // Cr�er la r�ponse avec les donn�es
    char* result = createSafeResponse(response, dataBuffer, dataSize);

    // Lib�rer le buffer temporaire
    delete[] dataBuffer;

    return result;
}

// Obtenir les configurations d'un cr�ateur sp�cifique
const char* ConfigController::handleGetConfigsByCreator(const char* creator) {
    // Note: Configs by creator are now available without authentication

    // Journalisation pour le d�bogage
    logMessage("[ConfigController] Getting configs for creator: " + std::string(creator));
    logMessage("[ConfigController] Public config directory exists: " +
        std::string(std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR) ? "yes" : "no"));

    // S'assurer que le r�pertoire des configurations publiques existe
    if (!std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR)) {
        try {
            std::filesystem::create_directories(PUBLIC_CONFIG_BASE_DIR);
            logMessage("[ConfigController] Created public configs directory: " + PUBLIC_CONFIG_BASE_DIR);
        }
        catch (const std::exception& e) {
            logMessage("[ConfigController] Failed to create public configs directory: " + std::string(e.what()));
            ConfigResponse response;
            response.status = 5; // Server error
            response.dataSize = 0;
            return createSafeResponse(response);
        }
    }

    // Collecter les configurations du cr�ateur
    std::vector<PublicConfigInfo> creatorConfigs;

    if (std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR)) {
        for (const auto& entry : std::filesystem::directory_iterator(PUBLIC_CONFIG_BASE_DIR)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                try {
                    std::ifstream file(entry.path());
                    if (file.is_open()) {
                        // V�rifier que le fichier est un JSON valide
                        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                        file.seekg(0, std::ios::beg); // Revenir au d�but du fichier

                        if (content.empty() || content[0] != '{') {
                            logMessage("[ConfigController] Invalid JSON format in file: " + entry.path().string());
                            continue;
                        }

                        nlohmann::json configJson;
                        file >> configJson;

                        // V�rifier la pr�sence des champs requis
                        if (!configJson.contains("name") || !configJson.contains("description") ||
                            !configJson.contains("creator") || !configJson.contains("date") ||
                            !configJson.contains("share_code")) {
                            logMessage("[ConfigController] Missing required fields in config file: " + entry.path().string());
                            continue;
                        }

                        std::string configCreator = configJson["creator"];

                        // V�rifier si c'est le bon cr�ateur
                        if (configCreator == creator) {
                            PublicConfigInfo info;
                            memset(&info, 0, sizeof(info)); // Important: initialiser � z�ro

                            std::string name = configJson["name"];
                            std::string description = configJson["description"];
                            std::string date = configJson["date"];
                            std::string shareCode = configJson["share_code"];

                            strncpy(info.name, name.c_str(), sizeof(info.name) - 1);
                            strncpy(info.description, description.c_str(), sizeof(info.description) - 1);
                            strncpy(info.creator, configCreator.c_str(), sizeof(info.creator) - 1);
                            strncpy(info.date, date.c_str(), sizeof(info.date) - 1);
                            strncpy(info.share_code, shareCode.c_str(), sizeof(info.share_code) - 1);

                            info.likes = configJson["likes"];
                            info.dislikes = configJson["dislikes"];
                            info.downloads = configJson["downloads"];

                            creatorConfigs.push_back(info);
                        }
                    }
                }
                catch (const std::exception& e) {
                    logMessage("[ConfigController] Error reading public config: " + entry.path().string() + ": " + e.what());
                }
            }
        }
    }

    // Journalisation du nombre de configurations trouv�es
    logMessage("[ConfigController] Found " + std::to_string(creatorConfigs.size()) +
        " configs for creator: " + std::string(creator));

    // Trier par date (plus r�cent d'abord)
    std::sort(creatorConfigs.begin(), creatorConfigs.end(), [](const auto& a, const auto& b) {
        return strcmp(a.date, b.date) > 0;
        });

    // Pr�parer la r�ponse: [count(uint32_t)][configInfo1][configInfo2]...
    uint32_t configsCount = static_cast<uint32_t>(creatorConfigs.size());
    size_t dataSize = sizeof(uint32_t) + configsCount * sizeof(PublicConfigInfo);

    // Cr�er un buffer pour les donn�es
    char* dataBuffer = new char[dataSize];
    memset(dataBuffer, 0, dataSize); // Initialiser � z�ro pour �viter des valeurs al�atoires

    // �crire le nombre de configurations
    *reinterpret_cast<uint32_t*>(dataBuffer) = configsCount;

    // �crire les informations de configuration
    if (configsCount > 0) {
        memcpy(dataBuffer + sizeof(uint32_t), creatorConfigs.data(), configsCount * sizeof(PublicConfigInfo));
    }

    // Journalisation de la r�ponse
    logMessage("[ConfigController] Returning " + std::to_string(configsCount) +
        " configs, data size: " + std::to_string(dataSize) + " bytes");

    // Cr�er la r�ponse finale
    ConfigResponse response;
    response.status = 0; // Success
    response.dataSize = static_cast<uint32_t>(dataSize);

    // Utiliser createSafeResponse pour construire la r�ponse
    char* responseBuffer = createSafeResponse(response, dataBuffer, dataSize);

    // Lib�rer le buffer temporaire
    delete[] dataBuffer;

    return responseBuffer;
}

// V�rifier si une configuration publique existe d�j�
const char* ConfigController::handlePublicConfigExists(const void* additionalData,
    size_t additionalDataSize) {

    // Note: Config existence check is now available without authentication

    // Extraire les param�tres
    std::string name;
    std::string creator;

    if (additionalData && additionalDataSize >= sizeof(CheckExistsRequest)) {
        const CheckExistsRequest* request = reinterpret_cast<const CheckExistsRequest*>(additionalData);
        name = request->name;
        creator = request->creator;
    }
    else {
        // R�ponse par d�faut si les donn�es sont invalides
        uint8_t* response = new uint8_t[sizeof(uint8_t)];
        *response = 0; // false
        return reinterpret_cast<char*>(response);
    }

    // V�rifier si la configuration existe
    bool exists = false;

    if (std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR)) {
        for (const auto& entry : std::filesystem::directory_iterator(PUBLIC_CONFIG_BASE_DIR)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                try {
                    std::ifstream file(entry.path());
                    if (file.is_open()) {
                        nlohmann::json configJson;
                        file >> configJson;

                        std::string configName = configJson["name"];
                        std::string configCreator = configJson["creator"];

                        // V�rifier si le nom et le cr�ateur correspondent
                        if (configName == name && (creator.empty() || configCreator == creator)) {
                            exists = true;
                            break;
                        }
                    }
                }
                catch (const std::exception& e) {
                    logMessage("[ConfigController] Error reading public config: " + entry.path().string() + ": " + e.what());
                }
            }
        }
    }

    // Pr�parer la r�ponse
    uint8_t* response = new uint8_t[sizeof(uint8_t)];
    *response = exists ? 1 : 0;

    return reinterpret_cast<char*>(response);
}

// Signaler une configuration inappropri�e
const char* ConfigController::handleReportConfig(const char* shareCode, const void* additionalData,
    size_t additionalDataSize, const char* hwid) {

    // V�rifier l'authentification
    if (!hwid || hwid[0] == '\0') {
        return createErrorResponse("Authentication required");
    }

    // Extraire la raison du signalement
    std::string reason;

    if (additionalData && additionalDataSize > 0) {
        reason = std::string(reinterpret_cast<const char*>(additionalData), additionalDataSize);
    }

    // V�rifier si la configuration existe
    std::string configPath = PUBLIC_CONFIG_BASE_DIR + "/" + std::string(shareCode) + ".json";

    if (!std::filesystem::exists(configPath)) {
        ConfigResponse response;
        response.status = 2; // Config not found
#ifdef _WIN32
    #ifdef _WIN32
    return _strdup(reinterpret_cast<const char*>(&response));
#else
    return strdup(reinterpret_cast<const char*>(&response));
#endif
#else
        return strdup(reinterpret_cast<const char*>(&response));
#endif
    }

    // Enregistrer le signalement dans un fichier s�par�
    std::string reportsDir = PUBLIC_CONFIG_BASE_DIR + "/reports";
    std::filesystem::create_directories(reportsDir);

    std::string reportFilename = reportsDir + "/" + shareCode + "_" +
        std::to_string(std::time(nullptr)) + ".json";

    nlohmann::json reportJson;
    reportJson["share_code"] = shareCode;
    reportJson["reporter"] = getUsernameFromHwid(hwid);
    reportJson["reporter_hwid"] = hwid;
    reportJson["reason"] = reason;
    reportJson["timestamp"] = TimeUtils::formatTime(std::time(nullptr));
    reportJson["ip_address"] = getIpFromSession("");

    std::ofstream reportFile(reportFilename);
    if (!reportFile.is_open()) {
        ConfigResponse response;
        response.status = 5; // Server error
#ifdef _WIN32
    #ifdef _WIN32
    return _strdup(reinterpret_cast<const char*>(&response));
#else
    return strdup(reinterpret_cast<const char*>(&response));
#endif
#else
        return strdup(reinterpret_cast<const char*>(&response));
#endif
    }

    reportFile << reportJson.dump(4);

    // Ajouter un marqueur au fichier de configuration pour indiquer qu'il a �t� signal�
    try {
        std::ifstream configFile(configPath);
        if (configFile.is_open()) {
            nlohmann::json configJson;
            configFile >> configJson;
            configFile.close();

            // Incr�menter le compteur de signalements
            int reportCount = 0;
            if (configJson.contains("report_count")) {
                reportCount = configJson["report_count"];
            }
            configJson["report_count"] = reportCount + 1;

            // Ajouter le dernier motif de signalement
            configJson["last_report_reason"] = reason;

            // Sauvegarder le fichier mis � jour
            std::ofstream outFile(configPath);
            outFile << configJson.dump(4);
        }
    }
    catch (const std::exception& e) {
        logMessage("[ConfigController] Error updating config after report: ");
    }

    // Notifier les administrateurs (impl�mentation selon votre syst�me)
    notifyAdminsAboutReport(shareCode, reason, getUsernameFromHwid(hwid));

    // Pr�parer la r�ponse
    ConfigResponse response;
    response.status = 0; // Success

#ifdef _WIN32
    return _strdup(reinterpret_cast<const char*>(&response));
#else
    return strdup(reinterpret_cast<const char*>(&response));
#endif
}

// Server-side: ConfigController.cpp
bool ConfigController::hasUserVoted(const char* hwid, const char* shareCode) {
    // Path to the vote file
    std::string votesDir = PUBLIC_CONFIG_BASE_DIR + "/votes";
    std::string voteFilename = votesDir + "/" + shareCode + "_" + hwid + ".json";

    // Check if the file exists
    return std::filesystem::exists(voteFilename);
}

bool ConfigController::hasUserLiked(const char* hwid, const char* shareCode) {
    // Path to the vote file
    std::string votesDir = PUBLIC_CONFIG_BASE_DIR + "/votes";
    std::string voteFilename = votesDir + "/" + shareCode + "_" + hwid + ".json";

    // Check if the file exists
    if (std::filesystem::exists(voteFilename)) {
        try {
            std::ifstream file(voteFilename);
            if (file.is_open()) {
                nlohmann::json voteJson;
                file >> voteJson;
                file.close();

                // Check if it's a like
                return voteJson["is_positive"] == true;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[ConfigController] Error reading vote file: " << voteFilename << ": " << e.what() << std::endl;
        }
    }

    return false;
}

bool ConfigController::hasUserDisliked(const char* hwid, const char* shareCode) {
    // Path to the vote file
    std::string votesDir = PUBLIC_CONFIG_BASE_DIR + "/votes";
    std::string voteFilename = votesDir + "/" + shareCode + "_" + hwid + ".json";

    // Check if the file exists
    if (std::filesystem::exists(voteFilename)) {
        try {
            std::ifstream file(voteFilename);
            if (file.is_open()) {
                nlohmann::json voteJson;
                file >> voteJson;
                file.close();

                // Check if it's a dislike
                return voteJson["is_positive"] == false;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[ConfigController] Error reading vote file: " << voteFilename << ": " << e.what() << std::endl;
        }
    }

    return false;
}
// M�thode pour obtenir le nombre total de configurations publiques
uint32_t ConfigController::getTotalPublicConfigCount() {
    uint32_t count = 0;

    if (std::filesystem::exists(PUBLIC_CONFIG_BASE_DIR)) {
        for (const auto& entry : std::filesystem::directory_iterator(PUBLIC_CONFIG_BASE_DIR)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                count++;
            }
        }
    }

    return count;
}

// M�thode utilitaire pour obtenir le nom d'utilisateur � partir du HWID
std::string ConfigController::getUsernameFromHwid(const char* hwid) {
    // Lire le fichier users.txt pour trouver le nom d'utilisateur
    std::ifstream file("users.txt");
    if (!file.is_open()) {
        return "Unknown";
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.find(hwid) != std::string::npos) {
            std::vector<std::string> parts;
            std::istringstream iss(line);
            std::string part;
            while (std::getline(iss, part, ';')) {
                parts.push_back(part);
            }

            if (!parts.empty()) {
                return parts[0]; // Le nom d'utilisateur est la premi�re partie
            }
        }
    }

    return "Unknown";
}

// V�rifier si un utilisateur est administrateur
bool ConfigController::isUserAdmin(const char* hwid) {
    // Lire le fichier d'administrateurs (admins.txt)
    std::ifstream file("admins.txt");
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Supprimer les espaces
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

        if (line == hwid) {
            return true;
        }
    }

    return false;
}

// Notifier les administrateurs d'un signalement
void ConfigController::notifyAdminsAboutReport(const std::string& shareCode,
    const std::string& reason, const std::string& reporter) {

    // Cette m�thode peut �tre impl�ment�e de diff�rentes fa�ons selon vos besoins
    // Par exemple, envoyer un e-mail, une notification Discord, etc.

    // Pour l'exemple, nous allons simplement l'enregistrer dans un fichier de log
    std::ofstream logFile("admin_reports.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << TimeUtils::formatTime(std::time(nullptr))
            << " - CONFIG REPORTED: ShareCode=" << shareCode
            << ", Reporter=" << reporter
            << ", Reason=" << reason << std::endl;
    }

    // Vous pourriez �galement impl�menter ici l'envoi d'un webhook Discord
    // si vous avez cette fonctionnalit�
}

// Obtenir l'adresse IP associ�e � une session
std::string ConfigController::getIpFromSession(const char* sessionToken) {
    // Cette m�thode d�pend de votre impl�mentation de gestion des sessions
    // Pour l'exemple, nous retournons une valeur factice
    return "0.0.0.0";
}

// M�thode principale qui redirige vers les handlers appropri�s
const char* ConfigController::handleRequest(const char* payload, const char* clientIp) {
    try {
        // V�rifier que le payload est valide
        if (!payload) {
            return createErrorResponse("Invalid payload");
        }

        // Extraire l'en-t�te de la requ�te
        ConfigRequest request;
        memcpy(&request, payload, sizeof(ConfigRequest));

        // Extraire les donn�es additionnelles si pr�sentes
        const void* additionalData = nullptr;
        if (request.dataSize > 0) {
            additionalData = payload + sizeof(ConfigRequest);
        }

        // Traiter selon l'op�ration
        switch (static_cast<ConfigOperation>(request.operation)) {
        case ConfigOperation::SAVE:
        {
            if (!additionalData || request.dataSize < sizeof(uint32_t)) {
                ConfigResponse response;
                memset(&response, 0, sizeof(response)); // AJOUTER CETTE LIGNE
                response.status = 1; // Invalid data
                response.dataSize = 0; // AJOUTER CETTE LIGNE
                return createSafeResponse(response);
            }

            uint32_t descSize = *reinterpret_cast<const uint32_t*>(additionalData);
            if (descSize + sizeof(uint32_t) > request.dataSize) {
                ConfigResponse response;
                memset(&response, 0, sizeof(response)); // AJOUTER CETTE LIGNE
                response.status = 1; // Invalid data
                response.dataSize = 0; // AJOUTER CETTE LIGNE
                return createSafeResponse(response);
            }

            std::string description(reinterpret_cast<const char*>(additionalData) + sizeof(uint32_t), descSize);
            const void* data = reinterpret_cast<const char*>(additionalData) + sizeof(uint32_t) + descSize;
            size_t dataSize = request.dataSize - sizeof(uint32_t) - descSize;

            // Authentication is now handled via request.hwid validation above

            if (saveUserConfig(request.hwid, request.configName, description.c_str(),
                reinterpret_cast<const char*>(data), dataSize)) {
                ConfigResponse response;
                memset(&response, 0, sizeof(response)); // AJOUTER CETTE LIGNE
                response.status = 0; // Success
                response.dataSize = 0; // AJOUTER CETTE LIGNE
                return createSafeResponse(response);
            }
            else {
                ConfigResponse response;
                memset(&response, 0, sizeof(response)); // AJOUTER CETTE LIGNE
                response.status = 5; // Server error
                response.dataSize = 0; // AJOUTER CETTE LIGNE
                return createSafeResponse(response);
            }
            break;
        }

        case ConfigOperation::LOAD:
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            std::string description;
            std::vector<uint8_t> data;

            if (loadUserConfig(request.hwid, request.configName, description, data)) {
                uint32_t descSize = static_cast<uint32_t>(description.size());
                size_t responseSize = sizeof(uint32_t) + description.size() + data.size();

                char* response = new char[responseSize];
                memcpy(response, &descSize, sizeof(uint32_t));
                memcpy(response + sizeof(uint32_t), description.c_str(), description.size());
                memcpy(response + sizeof(uint32_t) + description.size(), data.data(), data.size());

                ConfigResponse header;
                header.status = 0; // Success
                header.dataSize = static_cast<uint32_t>(responseSize);

                size_t fullResponseSize = sizeof(ConfigResponse) + responseSize;
                char* fullResponse = new char[fullResponseSize];
                memcpy(fullResponse, &header, sizeof(ConfigResponse));
                memcpy(fullResponse + sizeof(ConfigResponse), response, responseSize);

                delete[] response;
                return fullResponse;
            }
            else {
                ConfigResponse response;
                response.status = 2; // Not found
                return createSafeResponse(response);
            }
            break;
        }

        case ConfigOperation::MODIFY:
        {
            if (!additionalData || request.dataSize < sizeof(uint32_t)) {
                ConfigResponse response;
                response.status = 1; // Invalid data
                return createSafeResponse(response);
            }

            uint32_t descSize = *reinterpret_cast<const uint32_t*>(additionalData);
            if (descSize + sizeof(uint32_t) > request.dataSize) {
                ConfigResponse response;
                response.status = 1; // Invalid data
                return createSafeResponse(response);
            }

            std::string description(reinterpret_cast<const char*>(additionalData) + sizeof(uint32_t), descSize);
            const void* data = reinterpret_cast<const char*>(additionalData) + sizeof(uint32_t) + descSize;
            size_t dataSize = request.dataSize - sizeof(uint32_t) - descSize;

            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            if (modifyUserConfig(request.hwid, request.configName, description.c_str(),
                reinterpret_cast<const char*>(data), dataSize)) {
                ConfigResponse response;
                response.status = 0; // Success
                return createSafeResponse(response);
            }
            else {
                ConfigResponse response;
                response.status = 2; // Not found
                return createSafeResponse(response);
            }
            break;
        }

        case ConfigOperation::LIST:
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            std::string listResult = listUserConfigs(request.hwid);

            ConfigResponse header;
            header.status = 0; // Success
            header.dataSize = static_cast<uint32_t>(listResult.size());

            size_t fullResponseSize = sizeof(ConfigResponse) + listResult.size();
            char* response = new char[fullResponseSize];
            memcpy(response, &header, sizeof(ConfigResponse));
            memcpy(response + sizeof(ConfigResponse), listResult.c_str(), listResult.size());

            return response;
            break;
        }

        case ConfigOperation::DELETEE:
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            if (deleteUserConfig(request.hwid, request.configName)) {
                ConfigResponse response;
                response.status = 0; // Success
                return createSafeResponse(response);
            }
            else {
                ConfigResponse response;
                response.status = 2; // Not found
                return createSafeResponse(response);
            }
            break;
        }

        case static_cast<ConfigOperation>(ConfigPublicOperation::PUBLISH):
        {
            if (!additionalData || request.dataSize < sizeof(uint32_t)) {
                ConfigResponse response;
                response.status = 1; // Invalid data
                return createSafeResponse(response);
            }

            // Format: [creatorLength(4)][creator][allowAnonymous(bool)]
            uint32_t creatorLen = *reinterpret_cast<const uint32_t*>(additionalData);
            if (sizeof(uint32_t) + creatorLen + sizeof(bool) > request.dataSize) {
                ConfigResponse response;
                response.status = 1; // Invalid data
                return createSafeResponse(response);
            }

            std::string creator(reinterpret_cast<const char*>(additionalData) + sizeof(uint32_t), creatorLen);
            bool allowAnonymous = *reinterpret_cast<const bool*>(
                reinterpret_cast<const char*>(additionalData) + sizeof(uint32_t) + creatorLen);

            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            std::string shareCode;
            if (publishUserConfig(request.hwid, request.configName, creator.c_str(), allowAnonymous)) {
                // La m�thode a g�n�r� un code de partage
                ConfigResponse header;
                header.status = 0; // Success
                header.dataSize = static_cast<uint32_t>(shareCode.size());

                size_t fullResponseSize = sizeof(ConfigResponse) + shareCode.size();
                char* response = new char[fullResponseSize];
                memcpy(response, &header, sizeof(ConfigResponse));
                memcpy(response + sizeof(ConfigResponse), shareCode.c_str(), shareCode.size());

                return response;
            }
            else {
                ConfigResponse response;
                response.status = 5; // Server error
                return createSafeResponse(response);
            }
            break;
        }

        case static_cast<ConfigOperation>(ConfigPublicOperation::LIST_PUBLIC):
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            // V�rifier s'il s'agit d'une demande de statistiques
            if (additionalData && request.dataSize == sizeof(uint8_t)) {
                uint8_t checkOnly = *reinterpret_cast<const uint8_t*>(additionalData);
                if (checkOnly == 1) {
                    // Retourner juste le timestamp de la derni�re mise � jour
                    uint32_t latestTimestamp = static_cast<uint32_t>(std::time(nullptr));
                    char* response = new char[sizeof(uint32_t)];
                    *reinterpret_cast<uint32_t*>(response) = latestTimestamp;
                    return response;
                }
            }

            std::string listResult = listPublicConfigs();

            ConfigResponse header;
            header.status = 0; // Success
            header.dataSize = static_cast<uint32_t>(listResult.size());

            size_t fullResponseSize = sizeof(ConfigResponse) + listResult.size();
            char* response = new char[fullResponseSize];
            memcpy(response, &header, sizeof(ConfigResponse));
            memcpy(response + sizeof(ConfigResponse), listResult.c_str(), listResult.size());

            return response;
            break;
        }

        case static_cast<ConfigOperation>(ConfigPublicOperation::DOWNLOAD):
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            return handleDownloadPublicConfigToServer(request.configName, request.hwid);
        }

        case static_cast<ConfigOperation>(ConfigPublicOperation::RATE):
        {
            const void* rateData = nullptr;
            size_t rateDataSize = 0;

            // V�rifier si des donn�es suppl�mentaires sont disponibles
            if (request.dataSize > 0) {
                rateData = payload + sizeof(ConfigRequest);
                rateDataSize = request.dataSize;
            }

            return handleRatePublicConfig(request.configName, rateData, rateDataSize, request.hwid);
            // Ne pas mettre de break car le return termine d�j� la fonction
        }

        // Nouvelles op�rations
        case static_cast<ConfigOperation>(ConfigPublicOperation::UNPUBLISH):
        {
            // Authentication is now handled via request.hwid validation above

            std::string configPath = PUBLIC_CONFIG_BASE_DIR + "/" + std::string(request.configName) + ".json";
            if (!std::filesystem::exists(configPath)) {
                ConfigResponse response;
                memset(&response, 0, sizeof(response)); // IMPORTANT: Initialiser � z�ro
                response.status = 2; // Config not found
                response.dataSize = 0;
                return createSafeResponse(response);
            }

            std::ifstream file(configPath);
            if (!file.is_open()) {
                ConfigResponse response;
                memset(&response, 0, sizeof(response)); // IMPORTANT: Initialiser � z�ro
                response.status = 5; // Server error
                response.dataSize = 0;
                return createSafeResponse(response);
            }

            nlohmann::json configJson;
            file >> configJson;
            file.close();

            // Utiliser real_creator au lieu de creator pour les configs anonymes
            std::string creator = configJson["creator"];
            std::string realCreator = configJson.contains("real_creator") ?
                configJson["real_creator"].get<std::string>() : creator;

            // V�rifier si l'utilisateur peut supprimer cette configuration
            std::string username = getUsernameFromHwid(request.hwid);
            bool isAdmin = isUserAdmin(request.hwid);
            bool isOwner = (username == realCreator);

            if (!isOwner && !isAdmin) {
                ConfigResponse response;
                memset(&response, 0, sizeof(response)); // IMPORTANT: Initialiser � z�ro
                response.status = 3; // Access denied
                response.dataSize = 0;
                return createSafeResponse(response);
            }

            // Supprimer le fichier
            if (std::filesystem::remove(configPath)) {
                ConfigResponse response;
                memset(&response, 0, sizeof(response)); // IMPORTANT: Initialiser � z�ro
                response.status = 0; // Success
                response.dataSize = 0; // Pas de donn�es � retourner

                logMessage("Config unpublished: " + std::string(request.configName) +
                    " by " + getUsernameFromHwid(request.hwid));

                return createSafeResponse(response);
            }
            else {
                ConfigResponse response;
                memset(&response, 0, sizeof(response)); // IMPORTANT: Initialiser � z�ro
                response.status = 5; // Server error
                response.dataSize = 0;
                return createSafeResponse(response);
            }
            break;
        }

        case static_cast<ConfigOperation>(ConfigPublicOperation::PREVIEW):
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            return handlePreviewPublicConfig(request.configName);
        }

        // Dans handleRequest, remplacer les sections "// Impl�menter..." par:

        case static_cast<ConfigOperation>(ConfigPublicOperation::UPDATE_PUBLIC):
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            return handleUpdatePublicConfig(request, additionalData, request.dataSize, request.hwid);
        }

        // Dans la m�thode handleRequest, ajouter ce case :
        case static_cast<ConfigOperation>(ConfigPublicOperation::LIST_MY_PUBLIC):
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            return handleListMyPublicConfigs(request.hwid);
        }

        case static_cast<ConfigOperation>(ConfigPublicOperation::LIST_PUBLIC_PAGINATED):
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            return handleListPublicConfigsWithPagination(additionalData, request.dataSize);

        }

        case static_cast<ConfigOperation>(ConfigPublicOperation::CHECK_UPDATES):
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            return handleCheckForConfigUpdates();
        }

        case static_cast<ConfigOperation>(ConfigPublicOperation::SEARCH):
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            return handleSearchPublicConfigs(additionalData, request.dataSize);
        }

        case static_cast<ConfigOperation>(ConfigPublicOperation::GET_POPULAR):
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            return handleGetMostPopularConfigs(additionalData, request.dataSize);
        }

        case static_cast<ConfigOperation>(ConfigPublicOperation::GET_RECENT):
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            return handleGetRecentConfigs(additionalData, request.dataSize);
        }

        case static_cast<ConfigOperation>(ConfigPublicOperation::GET_BY_CREATOR):
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            // Utiliser le nom de configuration directement
            return handleGetConfigsByCreator(request.configName);
        }

        case static_cast<ConfigOperation>(ConfigPublicOperation::REPORT):
        {
            if (!request.hwid || request.hwid[0] == '\0') {
                ConfigResponse response;
                response.status = 3; // Access denied
                return createSafeResponse(response);
            }

            // Utiliser le nom de configuration directement et faire les conversions appropri�es
            return handleReportConfig(request.configName, additionalData, request.dataSize, request.hwid);
        }

        default:
            // G�rer les op�rations non support�es
            ConfigResponse response;
            response.status = 3; // Op�ration non support�e
            return createSafeResponse(response);
        }
    }
    catch (const std::exception& e) {
        logMessage("Error processing request: " + std::string(e.what()));
        return createErrorResponse(e.what());
    }

    // Ceci ne devrait jamais �tre atteint
    ConfigResponse response;
    response.status = 5; // Server error
    return createSafeResponse(response);
}