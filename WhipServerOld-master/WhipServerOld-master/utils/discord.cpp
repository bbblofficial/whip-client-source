#include "Discord.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#include <wininet.h>
#else
#include <unistd.h>
#include "native_http.h"
#endif

#ifdef _WIN32
#pragma comment(lib, "winhttp.lib")
#endif

#ifdef _WIN32
// Utility function to convert std::string to std::wstring (Windows only)
std::wstring stringToWstring(const std::string& str) {
    int len;
    int slength = (int)str.length() + 1;
    len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), slength, 0, 0);
    std::wstring r(len, L'\0');
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), slength, &r[0], len);
    return r;
}
#endif

// Utility function to get current timestamp in ISO 8601 format
std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &in_time_t);
#else
    gmtime_r(&in_time_t, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// Utility function to escape JSON strings
// Cette fonction corrig�e doit remplacer la fonction escapeJsonString actuelle dans Discord.cpp

// Utility function to escape JSON strings with proper UTF-8 handling
std::string escapeJsonString(const std::string& input) {
    std::ostringstream ss;
    for (auto iter = input.cbegin(); iter != input.cend(); iter++) {
        unsigned char c = static_cast<unsigned char>(*iter);

        if (c < 128) {
            // ASCII characters
            switch (c) {
            case '\"': ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b"; break;
            case '\f': ss << "\\f"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:
                // Check for control characters
                if (c < 32) {
                    // Format control characters as \uXXXX
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    ss << buf;
                }
                else {
                    ss << c;
                }
                break;
            }
        }
        else {
            // Non-ASCII characters (UTF-8)
            // Just pass them through as-is for proper Unicode handling
            ss << c;
        }
    }
    return ss.str();
}

// DiscordEmbed implementation
DiscordEmbed::DiscordEmbed(const std::optional<std::string>& title, const std::optional<std::string>& description)
    : title(title), description(description) {
}

void DiscordEmbed::setTitle(const std::string& title) {
    this->title = title;
}

void DiscordEmbed::setDescription(const std::string& description) {
    this->description = description;
}

void DiscordEmbed::setUrl(const std::string& url) {
    this->url = url;
}

void DiscordEmbed::setTimestamp(const std::optional<std::string>& timestamp) {
    if (timestamp) {
        this->timestamp = timestamp.value();
    }
    else {
        this->timestamp = getCurrentTimestamp();
    }
}

void DiscordEmbed::setColor(int color) {
    this->color = color;
}

void DiscordEmbed::setFooter(const std::string& text, const std::optional<std::string>& icon_url) {
    std::map<std::string, std::optional<std::string>> footerMap;
    footerMap["text"] = text;
    footerMap["icon_url"] = icon_url;
    this->footer = footerMap;
}

void DiscordEmbed::setImage(const std::string& url, const std::optional<std::string>& proxy_url, const std::optional<int>& height, const std::optional<int>& width) {
    std::map<std::string, std::optional<std::variant<std::string, int>>> imageMap;
    imageMap["url"] = url;
    if (proxy_url) {
        std::variant<std::string, int> proxyUrlVar = proxy_url.value();
        imageMap["proxy_url"] = proxyUrlVar;
    }
    if (height) {
        std::variant<std::string, int> heightVar = height.value();
        imageMap["height"] = heightVar;
    }
    if (width) {
        std::variant<std::string, int> widthVar = width.value();
        imageMap["width"] = widthVar;
    }
    this->image = imageMap;
}

void DiscordEmbed::setThumbnail(const std::string& url, const std::optional<std::string>& proxy_url, const std::optional<int>& height, const std::optional<int>& width) {
    std::map<std::string, std::optional<std::variant<std::string, int>>> thumbnailMap;
    thumbnailMap["url"] = url;
    if (proxy_url) {
        std::variant<std::string, int> proxyUrlVar = proxy_url.value();
        thumbnailMap["proxy_url"] = proxyUrlVar;
    }
    if (height) {
        std::variant<std::string, int> heightVar = height.value();
        thumbnailMap["height"] = heightVar;
    }
    if (width) {
        std::variant<std::string, int> widthVar = width.value();
        thumbnailMap["width"] = widthVar;
    }
    this->thumbnail = thumbnailMap;
}

void DiscordEmbed::setVideo(const std::optional<std::string>& url, const std::optional<int>& height, const std::optional<int>& width) {
    std::map<std::string, std::optional<std::variant<std::string, int>>> videoMap;
    if (url) {
        std::variant<std::string, int> urlVar = url.value();
        videoMap["url"] = urlVar;
    }
    if (height) {
        std::variant<std::string, int> heightVar = height.value();
        videoMap["height"] = heightVar;
    }
    if (width) {
        std::variant<std::string, int> widthVar = width.value();
        videoMap["width"] = widthVar;
    }
    this->video = videoMap;
}

void DiscordEmbed::setProvider(const std::optional<std::string>& name, const std::optional<std::string>& url) {
    std::map<std::string, std::optional<std::string>> providerMap;
    providerMap["name"] = name;
    providerMap["url"] = url;
    this->provider = providerMap;
}

void DiscordEmbed::setAuthor(const std::string& name, const std::optional<std::string>& url, const std::optional<std::string>& icon_url, const std::optional<std::string>& proxy_icon_url) {
    std::map<std::string, std::optional<std::string>> authorMap;
    authorMap["name"] = name;
    authorMap["url"] = url;
    authorMap["icon_url"] = icon_url;
    authorMap["proxy_icon_url"] = proxy_icon_url;
    this->author = authorMap;
}

void DiscordEmbed::addField(const std::string& name, const std::string& value, bool inline_field) {
    std::map<std::string, std::optional<std::variant<std::string, bool>>> field;
    std::variant<std::string, bool> nameVar = name;
    std::variant<std::string, bool> valueVar = value;
    std::variant<std::string, bool> inlineVar = inline_field;
    field["name"] = nameVar;
    field["value"] = valueVar;
    field["inline"] = inlineVar;
    this->fields.push_back(field);
}

void DiscordEmbed::removeField(size_t index) {
    if (index < this->fields.size()) {
        this->fields.erase(this->fields.begin() + index);
    }
}

std::string DiscordEmbed::toJson() const {
    std::ostringstream ss;
    ss << "{";

    // Title
    if (title) ss << "\"title\":\"" << escapeJsonString(*title) << "\",";

    // Description
    if (description) ss << "\"description\":\"" << escapeJsonString(*description) << "\",";

    // URL
    if (url) ss << "\"url\":\"" << escapeJsonString(*url) << "\",";

    // Timestamp
    if (timestamp) ss << "\"timestamp\":\"" << escapeJsonString(*timestamp) << "\",";

    // Color
    if (color) ss << "\"color\":" << *color << ",";

    // Footer
    if (footer) {
        ss << "\"footer\":{";
        for (const auto& [key, value] : *footer) {
            if (value) ss << "\"" << key << "\":\"" << escapeJsonString(*value) << "\",";
        }
        // Only remove trailing comma if we added at least one entry
        if (footer->size() > 0) {
            ss.seekp(-1, ss.cur); // Remove trailing comma
        }
        ss << "},";
    }

    // Image - FIXED to safely handle variants
    if (image) {
        ss << "\"image\":{";
        for (const auto& [key, value] : *image) {
            if (value) {
                try {
                    if (key == "url" || key == "proxy_url") {
                        // Assume these are always strings
                        ss << "\"" << key << "\":\"" << escapeJsonString(std::get<std::string>(*value)) << "\",";
                    }
                    else if (key == "height" || key == "width") {
                        // These could be integers
                        if (std::holds_alternative<int>(*value)) {
                            ss << "\"" << key << "\":" << std::get<int>(*value) << ",";
                        }
                    }
                }
                catch (const std::bad_variant_access&) {
                    std::cerr << "[Discord] Warning: Bad variant access in image for key: " << key << std::endl;
                    // Skip this field
                }
            }
        }
        // Only remove trailing comma if we added at least one entry
        if (ss.tellp() > 0 && ss.str().back() == ',') {
            ss.seekp(-1, ss.cur); // Remove trailing comma
        }
        ss << "},";
    }

    // Thumbnail - FIXED to safely handle variants
    if (thumbnail) {
        ss << "\"thumbnail\":{";
        for (const auto& [key, value] : *thumbnail) {
            if (value) {
                try {
                    if (key == "url" || key == "proxy_url") {
                        // Assume these are always strings
                        ss << "\"" << key << "\":\"" << escapeJsonString(std::get<std::string>(*value)) << "\",";
                    }
                    else if (key == "height" || key == "width") {
                        // These could be integers
                        if (std::holds_alternative<int>(*value)) {
                            ss << "\"" << key << "\":" << std::get<int>(*value) << ",";
                        }
                    }
                }
                catch (const std::bad_variant_access&) {
                    std::cerr << "[Discord] Warning: Bad variant access in thumbnail for key: " << key << std::endl;
                    // Skip this field
                }
            }
        }
        // Only remove trailing comma if we added at least one entry
        if (ss.tellp() > 0 && ss.str().back() == ',') {
            ss.seekp(-1, ss.cur); // Remove trailing comma
        }
        ss << "},";
    }

    // Video - FIXED to safely handle variants
    if (video) {
        ss << "\"video\":{";
        for (const auto& [key, value] : *video) {
            if (value) {
                try {
                    if (key == "url") {
                        // Assume url is always a string
                        ss << "\"" << key << "\":\"" << escapeJsonString(std::get<std::string>(*value)) << "\",";
                    }
                    else if (key == "height" || key == "width") {
                        // These could be integers
                        if (std::holds_alternative<int>(*value)) {
                            ss << "\"" << key << "\":" << std::get<int>(*value) << ",";
                        }
                    }
                }
                catch (const std::bad_variant_access&) {
                    std::cerr << "[Discord] Warning: Bad variant access in video for key: " << key << std::endl;
                    // Skip this field
                }
            }
        }
        // Only remove trailing comma if we added at least one entry
        if (ss.tellp() > 0 && ss.str().back() == ',') {
            ss.seekp(-1, ss.cur); // Remove trailing comma
        }
        ss << "},";
    }

    // Provider
    if (provider) {
        ss << "\"provider\":{";
        for (const auto& [key, value] : *provider) {
            if (value) ss << "\"" << key << "\":\"" << escapeJsonString(*value) << "\",";
        }
        // Only remove trailing comma if we added at least one entry
        if (provider->size() > 0) {
            ss.seekp(-1, ss.cur); // Remove trailing comma
        }
        ss << "},";
    }

    // Author
    if (author) {
        ss << "\"author\":{";
        for (const auto& [key, value] : *author) {
            if (value) ss << "\"" << key << "\":\"" << escapeJsonString(*value) << "\",";
        }
        // Only remove trailing comma if we added at least one entry
        if (author->size() > 0) {
            ss.seekp(-1, ss.cur); // Remove trailing comma
        }
        ss << "},";
    }

    // Fields - FIXED to safely handle variants
    if (!fields.empty()) {
        ss << "\"fields\":[";
        for (const auto& field : fields) {
            ss << "{";
            for (const auto& [key, value] : field) {
                if (value) {
                    try {
                        if (key == "name" || key == "value") {
                            // These are always strings
                            ss << "\"" << key << "\":\"" << escapeJsonString(std::get<std::string>(*value)) << "\",";
                        }
                        else if (key == "inline") {
                            // This is a boolean
                            if (std::holds_alternative<bool>(*value)) {
                                ss << "\"" << key << "\":" << (std::get<bool>(*value) ? "true" : "false") << ",";
                            }
                        }
                    }
                    catch (const std::bad_variant_access&) {
                        std::cerr << "[Discord] Warning: Bad variant access in field for key: " << key << std::endl;
                        // Skip this field
                    }
                }
            }
            // Only remove trailing comma if we added at least one entry
            if (ss.tellp() > 0 && ss.str().back() == ',') {
                ss.seekp(-1, ss.cur); // Remove trailing comma
            }
            ss << "},";
        }
        // Only remove trailing comma if we added at least one entry
        if (!fields.empty()) {
            ss.seekp(-1, ss.cur); // Remove trailing comma
        }
        ss << "],";
    }

    // Remove trailing comma if exists
    if (ss.tellp() > 0 && ss.str().back() == ',') {
        ss.seekp(-1, ss.cur);
    }

    ss << "}";
    return ss.str();
}

// DiscordWebhook implementation
DiscordWebhook::DiscordWebhook(const std::string& url) : url(url) {}

void DiscordWebhook::addEmbed(const DiscordEmbed& embed) {
    this->embeds.push_back(embed);
}

void DiscordWebhook::removeEmbed(size_t index) {
    if (index < this->embeds.size()) {
        this->embeds.erase(this->embeds.begin() + index);
    }
}

void DiscordWebhook::clearEmbeds() {
    this->embeds.clear();
}

void DiscordWebhook::addFile(const std::string& filename, const std::vector<uint8_t>& file_content) {
    this->files[filename] = file_content;
}

void DiscordWebhook::removeFile(const std::string& filename) {
    this->files.erase(filename);
}

void DiscordWebhook::clearFiles() {
    this->files.clear();
}

void DiscordWebhook::setContent(const std::string& content) {
    this->content = content;
}

void DiscordWebhook::setAvatarUrl(const std::string& avatar_url) {
    this->avatar_url = avatar_url;
}

void DiscordWebhook::setUsername(const std::string& username) {
    this->username = username;
}

void DiscordWebhook::setTTS(bool tts) {
    this->tts = tts;
}

void DiscordWebhook::setAllowedMentions(const std::map<std::string, std::vector<std::string>>& allowed_mentions) {
    this->allowed_mentions = allowed_mentions;
}

void DiscordWebhook::setProxies(const std::map<std::string, std::string>& proxies) {
    this->proxies = proxies;
}

void DiscordWebhook::setTimeout(int timeout) {
    this->timeout = timeout;
}

void DiscordWebhook::setRateLimitRetry(bool rate_limit_retry) {
    this->rate_limit_retry = rate_limit_retry;
}

void DiscordWebhook::setThreadId(const std::string& thread_id) {
    this->thread_id = thread_id;
}

void DiscordWebhook::setThreadName(const std::string& thread_name) {
    this->thread_name = thread_name;
}

void DiscordWebhook::setWait(bool wait) {
    this->wait = wait;
}

std::string DiscordWebhook::toJson() const {
    std::ostringstream ss;
    ss << "{";
    if (content) ss << "\"content\":\"" << escapeJsonString(*content) << "\",";
    if (avatar_url) ss << "\"avatar_url\":\"" << escapeJsonString(*avatar_url) << "\",";
    if (username) ss << "\"username\":\"" << escapeJsonString(*username) << "\",";
    if (tts) ss << "\"tts\":" << (*tts ? "true" : "false") << ",";

    // Allowed mentions
    if (allowed_mentions) {
        ss << "\"allowed_mentions\":{";
        for (const auto& [key, value] : *allowed_mentions) {
            ss << "\"" << key << "\":[";
            for (const auto& item : value) {
                ss << "\"" << escapeJsonString(item) << "\",";
            }
            if (!value.empty()) {
                ss.seekp(-1, ss.cur); // Remove trailing comma
            }
            ss << "],";
        }
        if (!allowed_mentions->empty()) {
            ss.seekp(-1, ss.cur); // Remove trailing comma
        }
        ss << "},";
    }

    // Thread ID
    if (thread_id) ss << "\"thread_id\":\"" << escapeJsonString(*thread_id) << "\",";

    // Wait
    if (wait) ss << "\"wait\":" << (*wait ? "true" : "false") << ",";

    // Embeds
    if (!embeds.empty()) {
        ss << "\"embeds\":[";
        for (const auto& embed : embeds) {
            ss << embed.toJson() << ",";
        }
        if (!embeds.empty()) {
            ss.seekp(-1, ss.cur); // Remove trailing comma
        }
        ss << "],";
    }

    // Remove trailing comma if exists
    if (ss.tellp() > 0 && ss.str().back() == ',') {
        ss.seekp(-1, ss.cur);
    }

    ss << "}";
    return ss.str();
}

void DiscordWebhook::execute() {
#ifdef _WIN32
    HINTERNET hSession = WinHttpOpen(L"A Discord Webhook Client/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cerr << "[Discord] WinHttpOpen failed: " << GetLastError() << std::endl;
        throw std::runtime_error("Failed to initialize WinHttp session");
    }

    URL_COMPONENTS urlComp;
    memset(&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t host[256];
    wchar_t path[256];
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = sizeof(host) / sizeof(wchar_t);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = sizeof(path) / sizeof(wchar_t);

    std::wstring wUrl = stringToWstring(url);

    if (!WinHttpCrackUrl(wUrl.c_str(), 0, 0, &urlComp)) {
        std::cerr << "[Discord] WinHttpCrackUrl failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Failed to parse webhook URL");
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cerr << "[Discord] WinHttpConnect failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Failed to connect to Discord servers");
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlComp.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, urlComp.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        std::cerr << "[Discord] WinHttpOpenRequest failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Failed to create HTTP request");
    }

    // Configurer les options de s�curit� pour SSL
    DWORD dwFlags = 0;
    DWORD dwBuffLen = sizeof(dwFlags);
    InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwBuffLen);
    dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    dwFlags |= SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    dwFlags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));

    std::string jsonPayload = toJson();

    // Debug: Print the JSON payload to help diagnose issues
    std::cout << "[Discord] JSON Payload: " << jsonPayload << std::endl;

    if (!WinHttpSendRequest(hRequest, L"Content-Type: application/json\r\n", -1, (LPVOID)jsonPayload.c_str(), jsonPayload.size(), jsonPayload.size(), 0)) {
        std::cerr << "[Discord] WinHttpSendRequest failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Failed to send HTTP request");
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        std::cerr << "[Discord] WinHttpReceiveResponse failed: " << GetLastError() << std::endl;
        throw std::runtime_error("Failed to receive HTTP response");
    }

    // Check status code
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);

    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
        std::cout << "[Discord] HTTP Status Code: " << statusCode << std::endl;

        if (statusCode >= 400) {
            // Read response body for error details
            DWORD bytesAvailable = 0;
            DWORD bytesRead = 0;
            std::string responseBody;

            do {
                WinHttpQueryDataAvailable(hRequest, &bytesAvailable);
                if (bytesAvailable > 0) {
                    char* buffer = new char[bytesAvailable + 1];
                    memset(buffer, 0, bytesAvailable + 1);

                    if (WinHttpReadData(hRequest, buffer, bytesAvailable, &bytesRead)) {
                        responseBody.append(buffer, bytesRead);
                    }

                    delete[] buffer;
                }
            } while (bytesAvailable > 0);

            std::cerr << "[Discord] Error response: " << responseBody << std::endl;
            throw std::runtime_error("Discord API returned an error: " + responseBody);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
#else
    // Implémentation Linux avec HTTP natif
    std::string jsonData = toJson();
    
    std::map<std::string, std::string> headers;
    headers["Content-Type"] = "application/json";
    headers["User-Agent"] = "AuthServer/1.0";
    
    try {
        // Note: Les webhooks Discord utilisent HTTPS, mais notre implémentation simple ne le supporte pas
        // Pour une utilisation en production, il faudrait soit:
        // 1. Utiliser un proxy HTTP local qui convertit HTTPS en HTTP
        // 2. Implémenter TLS/SSL natif
        // 3. Utiliser un service intermédiaire
        
        std::cerr << "[Discord] Warning: HTTPS not supported in native implementation" << std::endl;
        std::cerr << "[Discord] Webhook data that would be sent: " << jsonData << std::endl;
        
        // Pour le développement, on peut simuler l'envoi
        std::cout << "[Discord] Webhook simulated (HTTPS not supported in native mode)" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "[Discord] Failed to send webhook: " << e.what() << std::endl;
        throw std::runtime_error("Failed to send Discord webhook: " + std::string(e.what()));
    }
#endif
}