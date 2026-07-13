#pragma once
#include "../controller.h"
// #include "sessionManager.h" // Removed session management
#include "../../utils/Protocol/protocol.h"
#include "../../utils/SimpleWebhook.h"

// Types d'erreur supportÃ©s
enum class ErrorType : uint8_t {
    DEBUGGER_DETECTED = 0,
    HOOK_DETECTED = 1,
    VM_DETECTED = 2,
    UNKNOWN = 255
};

// Structure pour le payload d'erreur
#pragma pack(push, 1)
struct ErrorPayload {
    char sessionToken[320];    // Token de session chiffrÃ©
    uint8_t errorType;         // Type d'erreur
    uint32_t timestamp;        // Timestamp de l'erreur
    uint32_t screenshotSize;   // Taille de la capture d'Ã©cran (si prÃ©sente)
    uint8_t reserved[23];      // RÃ©servÃ© pour future utilisation - Contient le nom du débogueur si ErrorType::DEBUGGER_DETECTED
    // La capture d'Ã©cran suit cette structure dans le payload
};

struct ErrorResponse {
    uint8_t status;            // 0 = succÃ¨s, autres = erreur
    uint8_t reserved[31];      // RÃ©servÃ© pour future utilisation
};
#pragma pack(pop)

class ErrorController : public Controller {
private:
    // URL du webhook Discord
    static constexpr const char* WEBHOOK_URL = "https://discord.com/api/webhooks/1345771990774190143/zjjphYPJR8ZS_NPU3Tu7s5GXdUJxWNZA2edBnE_WMB2OXhMkJGv2uWCCO6kTetcvfizq";

    // Convertir le type d'erreur en chaÃ®ne lisible
    const char* getErrorTypeString(uint8_t errorType, const char* debuggerName = nullptr);

    // Obtenir les informations utilisateur Ã  partir du HWID
    const char* getUserByHwid(const char* hwid);

    bool removeUserByHwid(const char* hwid);

    // Envoyer le webhook Discord
    bool sendErrorWebhook(const char* username, const char* hwid, const char* sessionToken,
        const char* clientIp, uint8_t errorType, const char* screenshotPath, const char* debuggerName = nullptr);

public:
    ErrorController();
    const char* handleRequest(const char* payload, const char* clientIp = "n/a") override;
};