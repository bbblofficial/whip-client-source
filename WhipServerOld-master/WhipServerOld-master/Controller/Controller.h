#pragma once
#include <string>
#include "../utils/json/nlohmann/json.hpp"

class Controller {
public:
    virtual ~Controller() = default;

    virtual const char *handleRequest(const char *payload, const char *clientIp = "n/a") = 0;

protected:
    static const char *createErrorResponse(const char *message) {
        static std::string responseStr;
        responseStr = nlohmann::json{{"error", message}}.dump();
        return responseStr.c_str();
    }
};
