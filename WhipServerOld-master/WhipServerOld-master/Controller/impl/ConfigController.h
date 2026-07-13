#pragma once
#include "../controller.h"
// #include "sessionManager.h" // Removed session management
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include "../../utils/Protocol/protocol.h"
#include <set>
#include <iostream>

class ConfigController : public Controller {
private:
    // Chemin du dossier des configurations
    static const std::string CONFIG_BASE_DIR;
    static const std::string PUBLIC_CONFIG_BASE_DIR;

    // Structure pour stocker les informations de vote (HWID + shareCode = unique)
    struct VoteInfo {
        std::string hwid;
        std::string shareCode;
        bool isPositive;
    };

    // Map pour suivre les votes par utilisateur
    std::map<std::string, std::map<std::string, bool>> userVotes; // userHwid -> { shareCode -> vote }

    // Structures pour les requ�tes
    struct PaginationRequest {
        int32_t page;
        int32_t pageSize;
        char searchQuery[128];
    };

    struct SearchRequest {
        char query[128];
        int32_t maxResults;
    };

    struct CheckExistsRequest {
        char name[32];
        char creator[32];
    };

    // Dans configclientv2.h, ajouter � l'enum ConfigPublicOperation :
    enum class ConfigPublicOperation : uint8_t {
        PUBLISH = 10,
        LIST_PUBLIC = 11,
        DOWNLOAD = 12,
        RATE = 13,
        UNPUBLISH = 14,
        UPDATE_PUBLIC = 15,
        CHECK_UPDATES = 16,
        LIST_PUBLIC_PAGINATED = 17,
        SEARCH = 18,
        GET_POPULAR = 19,
        GET_RECENT = 20,
        GET_BY_CREATOR = 21,
        REPORT = 22,
        LIST_MY_PUBLIC = 23,
        PREVIEW = 24  // NOUVEAU
    };

    struct PublicConfigStats {
        uint32_t totalConfigs;
        uint32_t totalDownloads;
        uint32_t totalLikes;
        uint32_t totalDislikes;
        uint32_t activeUsers;
        uint32_t lastUpdateTimestamp;
    };

    // Ensemble d'utilisateurs actifs
    std::set<std::string> activeUsers;

    // M�thodes priv�es pour le traitement des requ�tes
    const char* handleUnpublishConfig(const char* shareCode, const char* hwid);
    const char* handleUpdatePublicConfig(const ConfigRequest& request, const void* additionalData, size_t additionalDataSize, const char* hwid);
    const char* handleListPublicConfigsWithPagination(const void* additionalData, size_t additionalDataSize);
    const char* handleCheckForConfigUpdates();
    const char* handleGetPublicConfigStats();
    const char* handleSearchPublicConfigs(const void* additionalData, size_t additionalDataSize);
    const char* handleGetMostPopularConfigs(const void* additionalData, size_t additionalDataSize);
    const char* handleGetRecentConfigs(const void* additionalData, size_t additionalDataSize);
    const char* handleGetConfigsByCreator(const char* creator);
    const char* handlePublicConfigExists(const void* additionalData, size_t additionalDataSize);
    const char* handleReportConfig(const char* shareCode, const void* additionalData, size_t additionalDataSize, const char* hwid);
    const char* handleListMyPublicConfigs(const char* hwid);
    const char* handleDownloadPublicConfigToServer(const char* shareCode, const char* hwid);
    const char* handlePreviewPublicConfig(const char* shareCode);

    bool hasUserAlreadyDownloadedConfig(const char* hwid, const char* shareCode);
    void recordUserDownload(const char* hwid, const char* shareCode, const std::string& savedConfigName);
    void removeUserDownloadRecord(const char* hwid, const char* shareCode);

    // M�thodes utilitaires
    bool hasUserRated(const char* hwid, const char* shareCode);
    bool hasUserLiked(const char* hwid, const char* shareCode);
    bool hasUserDisliked(const char* hwid, const char* shareCode);
    uint32_t getTotalPublicConfigCount();
    std::string getUsernameFromHwid(const char* hwid);
    bool isUserAdmin(const char* hwid);
    void notifyAdminsAboutReport(const std::string& shareCode, const std::string& reason, const std::string& reporter);
    std::string getIpFromSession(const char* sessionToken);

    // Utilitaires
    std::string getConfigFilePath(const char* hwid, const char* configName);
    std::string listUserConfigs(const char* hwid);
    bool saveUserConfig(const char* hwid, const char* configName,
        const char* description, const char* data, size_t dataSize);
    bool loadUserConfig(const char* hwid, const char* configName,
        std::string& description, std::vector<uint8_t>& data);
    bool deleteUserConfig(const char* hwid, const char* configName);
    bool modifyUserConfig(const char* hwid, const char* configName,
        const char* newDescription, const char* newData, size_t newDataSize);

    void logMessage(const std::string& message);

    // Fonctionnalit�s pour les configurations publiques
    std::string generateShareCode();
    bool publishUserConfig(const char* hwid, const char* configName,
        const char* creator, bool allowAnonymous);
    bool loadPublicConfig(const char* shareCode, std::string& name, std::string& description,
        std::string& creator, std::string& date, std::vector<uint8_t>& data);
    const char* listPublicConfigs();
    bool incrementDownloadCount(const char* shareCode);
    bool hasUserVoted(const char* hwid, const char* shareCode);

    const char* handleRatePublicConfig(const char* shareCode, const void* additionalData, size_t additionalDataSize, const char* hwid);

public:
    ConfigController();
    char* createSafeResponse(const ConfigResponse& response, const void* data = nullptr, size_t dataSize = 0);
    const char* handleRequest(const char* payload, const char* clientIp = "n/a") override;
};