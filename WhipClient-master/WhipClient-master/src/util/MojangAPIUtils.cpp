#include "../../includes/util/MojangAPIUtils.h"
#include "../../includes/util/whipJson.h"
#include <winhttp.h>

UUIDData MojangAPIUtils::fetchUUIDFromUsername(const std::string& username) {
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;
    std::string uuidString;
    bool success = false;

    int timeout = 3000;
    std::wstring wUsername;
    std::wstring path;
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);

    hSession = WinHttpOpen(
        L"Mozilla/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) goto cleanup;

    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    hConnect = WinHttpConnect(
        hSession,
        L"api.mojang.com",
        INTERNET_DEFAULT_HTTPS_PORT,
        0
    );

    if (!hConnect) goto cleanup;

    wUsername = std::wstring(username.begin(), username.end());
    path = L"/users/profiles/minecraft/" + wUsername;

    hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );

    if (!hRequest) goto cleanup;

    if (!WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0
    )) goto cleanup;

    if (!WinHttpReceiveResponse(hRequest, nullptr)) goto cleanup;

    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusCodeSize,
        WINHTTP_NO_HEADER_INDEX
    );

    if (statusCode != 200) goto cleanup;

    {
        std::string responseBody;
        DWORD bytesAvailable = 0;
        DWORD bytesRead = 0;
        char buffer[4096];

        do {
            if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) break;
            if (bytesAvailable == 0) break;

            DWORD toRead = (bytesAvailable < sizeof(buffer)) ? bytesAvailable : sizeof(buffer);
            if (!WinHttpReadData(hRequest, buffer, toRead, &bytesRead)) break;

            responseBody.append(buffer, bytesRead);
        } while (bytesRead > 0);

        if (parseMojangResponse(responseBody, uuidString)) {
            success = true;
        }
    }

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    if (success) {
        return convertMojangUUIDToData(uuidString);
    }

    return UUIDData();
}

bool MojangAPIUtils::parseMojangResponse(const std::string& jsonResponse, std::string& outUUID) {
    try {

        auto json = whip::WhipJsonValue::parse(jsonResponse);

        if (!json.contains("id")) {
            return false;
        }

        outUUID = json["id"].get<std::string>();

        if (outUUID.length() != 32) {
            return false;
        }

        for (char c : outUUID) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }

        return true;
    } catch (...) {

        return false;
    }
}

UUIDData MojangAPIUtils::convertMojangUUIDToData(const std::string& uuidStr) {

    if (uuidStr.length() != 32) return UUIDData();

    try {

        unsigned long long mostSigBits = std::stoull(uuidStr.substr(0, 16), nullptr, 16);

        unsigned long long leastSigBits = std::stoull(uuidStr.substr(16, 16), nullptr, 16);

        long long xor64 = mostSigBits ^ leastSigBits;
        jint hashCode = static_cast<jint>((xor64 >> 32) ^ xor64);

        return UUIDData(hashCode);
    } catch (...) {
        return UUIDData();
    }
}
