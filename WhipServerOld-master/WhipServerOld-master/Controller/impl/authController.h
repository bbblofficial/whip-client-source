#pragma once
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include "../controller.h"
#include "../../utils/string_utils.h"
#include "../../utils/time_utils.h"
#include "../../utils/Protocol/protocol.h"
#include "../../utils/SimpleWebhook.h" // Ajout de l'inclusion pour SimpleWebhook

// Forward declaration de VersionData si pas disponible
#ifndef VERSION_DATA_DEFINED
#define VERSION_DATA_DEFINED
#pragma pack(push, 1)
struct VersionData {
    int versionKey;
    char minecraftClass[128];
    char theMinecraftField[64];
    char launchedVersionField[64];
    char launchedVersionValue[32];
    uint8_t minecraftVersion;
    uint8_t minecraftLauncher;
    uint8_t classResolvingMethod;
    char specificClassLoaderClass[128];
    char specificClassLoaderField[64];
    char specificClassLoaderSig[64];
    uint8_t reserved[32];
};
#pragma pack(pop)
#endif

class AuthController : public Controller {
private:
    const char* vectorToString(const std::vector<uint8_t>& data);
    std::map<const char*, const char*> versionToMappingsFile;
    AuthPart1Response createPart1SuccessResponse(const char* hwid, const char* mappingContent);
    AuthPart2Response createPart2SuccessResponse(const char* username, const char* uuid, const char* mappingContent);
    AuthPart1Response createPart1ErrorResponse(const char* message);
    AuthPart2Response createPart2ErrorResponse(const char* message);
    bool validateHWID(const char* hwid);
    bool validateVersion(const char* version);
    bool validateProduct(const char* product);

    const char* getMappingContent(const char* version);
    const char* getVersionsContent();  // Nouvelle méthode pour obtenir le JSON des versions
    std::vector<const char*> readUsersFile();
    const char* getUserByHwid(const std::vector<const char*>& users, const char* hwid);

    // Nouvelles m�thodes pour g�rer les notifications Discord
    const char* getMinecraftVersionString(const char* version);
    const char* parseUsername(const char* userString);
    const char* parseUUID(const char* userString);
    
    // Méthodes pour gérer les deux parties du login
    const char* handleAuthPart1(const char* payload, const char* clientIp);
    
    // Méthodes de décryption AES
    const char* aesDecrypt(const char* input, const char* key);
    unsigned char* fromBase64(const char* input, size_t* output_len);
    std::vector<std::string> splitEncryptedPayload(const char* payload, const char* delimiter);

public:
    const char* handleAuthPart2(const char* payload, const char* clientIp);
    const char* handlePlayerInfoRequest(const char* payload, const char* clientIp);
    void notifyPlayerSession(const char* username, const char* uuid, const char* hwid, const char* clientIp);

    AuthController();
    // Implementation of pure virtual method from Controller base class
    const char* handleRequest(const char* payload, const char* clientIp = "n/a") override;
    
    // Méthode statique pour obtenir la taille des dernières données binaires
    static size_t getLastBinaryResponseSize();
};