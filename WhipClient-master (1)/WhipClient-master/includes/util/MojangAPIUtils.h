#pragma once

#include <string>
#include <windows.h>
#include "../wrapper/java/util/UUID.h"

class MojangAPIUtils {
public:

    static UUIDData fetchUUIDFromUsername(const std::string& username);

private:

    static bool parseMojangResponse(const std::string& jsonResponse, std::string& outUUID);

    static UUIDData convertMojangUUIDToData(const std::string& uuidStr);
};
