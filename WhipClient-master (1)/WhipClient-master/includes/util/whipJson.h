#ifndef WHIP_JSON_H
#define WHIP_JSON_H

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>
#include <utility>
#include <type_traits>
#include "TrackedString.h"

namespace whip {

enum class JsonType { Null, Bool, Int, Float, String, Array, Object };

class WhipJsonValue {
public:

    WhipJsonValue() = default;

    WhipJsonValue(bool val) : m_type(JsonType::Bool), m_bool(val) {}
    WhipJsonValue(int val) : m_type(JsonType::Int), m_int(val) {}
    WhipJsonValue(int64_t val) : m_type(JsonType::Int), m_int(val) {}
    WhipJsonValue(unsigned int val) : m_type(JsonType::Int), m_int(static_cast<int64_t>(val)) {}
    WhipJsonValue(float val) : m_type(JsonType::Float), m_float(val) {}
    WhipJsonValue(double val) : m_type(JsonType::Float), m_float(val) {}
    WhipJsonValue(const char* val) : m_type(JsonType::String), m_string(val ? val : "") {}
    WhipJsonValue(const std::string& val) : m_type(JsonType::String), m_string(val) {}

    ~WhipJsonValue() { clear(); }

    WhipJsonValue(const WhipJsonValue& o)
        : m_type(o.m_type), m_bool(o.m_bool), m_int(o.m_int), m_float(o.m_float),
          m_string(o.m_string), m_object(o.m_object), m_array(o.m_array) {}

    WhipJsonValue& operator=(const WhipJsonValue& o) {
        if (this != &o) {
            clear();
            m_type = o.m_type;
            m_bool = o.m_bool;
            m_int = o.m_int;
            m_float = o.m_float;
            m_string = o.m_string;
            m_object = o.m_object;
            m_array = o.m_array;
        }
        return *this;
    }

    WhipJsonValue(WhipJsonValue&& o) noexcept
        : m_type(o.m_type), m_bool(o.m_bool), m_int(o.m_int), m_float(o.m_float),
          m_string(std::move(o.m_string)), m_object(std::move(o.m_object)),
          m_array(std::move(o.m_array)) {
        o.m_type = JsonType::Null;
        o.m_bool = false;
        o.m_int = 0;
        o.m_float = 0.0;
    }

    WhipJsonValue& operator=(WhipJsonValue&& o) noexcept {
        if (this != &o) {
            clear();
            m_type = o.m_type;
            m_bool = o.m_bool;
            m_int = o.m_int;
            m_float = o.m_float;
            m_string = std::move(o.m_string);
            m_object = std::move(o.m_object);
            m_array = std::move(o.m_array);
            o.m_type = JsonType::Null;
            o.m_bool = false;
            o.m_int = 0;
            o.m_float = 0.0;
        }
        return *this;
    }

    WhipJsonValue& operator=(bool val) {
        clear();
        m_type = JsonType::Bool;
        m_bool = val;
        return *this;
    }

    WhipJsonValue& operator=(int val) {
        clear();
        m_type = JsonType::Int;
        m_int = val;
        return *this;
    }

    WhipJsonValue& operator=(int64_t val) {
        clear();
        m_type = JsonType::Int;
        m_int = val;
        return *this;
    }

    WhipJsonValue& operator=(float val) {
        clear();
        m_type = JsonType::Float;
        m_float = val;
        return *this;
    }

    WhipJsonValue& operator=(double val) {
        clear();
        m_type = JsonType::Float;
        m_float = val;
        return *this;
    }

    WhipJsonValue& operator=(const char* val) {
        clear();
        m_type = JsonType::String;
        m_string = val ? val : "";
        return *this;
    }

    WhipJsonValue& operator=(const std::string& val) {
        clear();
        m_type = JsonType::String;
        m_string = val;
        return *this;
    }

    WhipJsonValue& operator=(std::initializer_list<double> list) {
        clear();
        m_type = JsonType::Array;
        for (double v : list) {
            WhipJsonValue elem;
            elem.m_type = JsonType::Float;
            elem.m_float = v;
            m_array.push_back(std::move(elem));
        }
        return *this;
    }

    WhipJsonValue& operator=(std::initializer_list<float> list) {
        clear();
        m_type = JsonType::Array;
        for (float v : list) {
            WhipJsonValue elem;
            elem.m_type = JsonType::Float;
            elem.m_float = static_cast<double>(v);
            m_array.push_back(std::move(elem));
        }
        return *this;
    }

    WhipJsonValue& operator=(const std::vector<bool>& vec) {
        clear();
        m_type = JsonType::Array;
        for (bool v : vec) {
            WhipJsonValue elem;
            elem.m_type = JsonType::Bool;
            elem.m_bool = v;
            m_array.push_back(std::move(elem));
        }
        return *this;
    }

    WhipJsonValue& operator[](const char* key) {
        if (m_type == JsonType::Null) m_type = JsonType::Object;
        if (m_type != JsonType::Object) return *this;

        for (auto& [k, v] : m_object) {
            if (k == key) return v;
        }
        m_object.emplace_back(DynamicTrackedString(key), WhipJsonValue());
        return m_object.back().second;
    }

    WhipJsonValue& operator[](const std::string& key) {
        return operator[](key.c_str());
    }

    const WhipJsonValue& operator[](const char* key) const {
        if (m_type != JsonType::Object) return nullValue();
        for (const auto& [k, v] : m_object) {
            if (k == key) return v;
        }
        return nullValue();
    }

    const WhipJsonValue& operator[](const std::string& key) const {
        return operator[](key.c_str());
    }

    WhipJsonValue& operator[](size_t index) {
        if (m_type == JsonType::Null) m_type = JsonType::Array;
        if (m_type != JsonType::Array) return *this;
        while (m_array.size() <= index) m_array.emplace_back();
        return m_array[index];
    }

    const WhipJsonValue& operator[](size_t index) const {
        if (m_type != JsonType::Array || index >= m_array.size()) return nullValue();
        return m_array[index];
    }

    WhipJsonValue& operator[](int index) { return operator[](static_cast<size_t>(index)); }
    const WhipJsonValue& operator[](int index) const { return operator[](static_cast<size_t>(index)); }

    bool contains(const char* key) const {
        if (m_type != JsonType::Object) return false;
        for (const auto& [k, v] : m_object) {
            if (k == key) return true;
        }
        return false;
    }

    bool contains(const std::string& key) const {
        return contains(key.c_str());
    }

    std::string value(const char* key, const char* defaultVal) const {
        if (m_type != JsonType::Object) return defaultVal ? defaultVal : "";
        for (const auto& [k, v] : m_object) {
            if (k == key && v.m_type == JsonType::String) {
                return std::string(v.m_string.c_str());
            }
        }
        return defaultVal ? defaultVal : "";
    }

    std::string value(const char* key, const std::string& defaultVal) const {
        return value(key, defaultVal.c_str());
    }

    WhipJsonValue value(const char* key, const WhipJsonValue& defaultVal) const {
        if (m_type != JsonType::Object) return defaultVal;
        for (const auto& [k, v] : m_object) {
            if (k == key) return v;
        }
        return defaultVal;
    }

    template<typename T>
    T get() const {
        if constexpr (std::is_same_v<T, bool>) {
            return m_type == JsonType::Bool ? m_bool : false;
        } else if constexpr (std::is_same_v<T, int>) {
            if (m_type == JsonType::Int) return static_cast<int>(m_int);
            if (m_type == JsonType::Float) return static_cast<int>(m_float);
            return 0;
        } else if constexpr (std::is_same_v<T, float>) {
            if (m_type == JsonType::Float) return static_cast<float>(m_float);
            if (m_type == JsonType::Int) return static_cast<float>(m_int);
            return 0.0f;
        } else if constexpr (std::is_same_v<T, double>) {
            if (m_type == JsonType::Float) return m_float;
            if (m_type == JsonType::Int) return static_cast<double>(m_int);
            return 0.0;
        } else if constexpr (std::is_same_v<T, std::string>) {
            if (m_type == JsonType::String) return std::string(m_string.c_str());
            return std::string();
        } else if constexpr (std::is_same_v<T, std::vector<bool>>) {
            std::vector<bool> result;
            if (m_type == JsonType::Array) {
                for (const auto& elem : m_array) {
                    result.push_back(elem.get<bool>());
                }
            }
            return result;
        } else {
            static_assert(!std::is_same_v<T, T>, "Unsupported type for WhipJsonValue::get()");
            return T{};
        }
    }

    DynamicTrackedString getSecureString() const {
        if (m_type == JsonType::String) return DynamicTrackedString(m_string.c_str());
        return DynamicTrackedString();
    }

    bool is_null() const { return m_type == JsonType::Null; }
    bool is_boolean() const { return m_type == JsonType::Bool; }
    bool is_number() const { return m_type == JsonType::Int || m_type == JsonType::Float; }
    bool is_number_integer() const { return m_type == JsonType::Int; }
    bool is_number_float() const { return m_type == JsonType::Float; }
    bool is_string() const { return m_type == JsonType::String; }
    bool is_array() const { return m_type == JsonType::Array; }
    bool is_object() const { return m_type == JsonType::Object; }

    size_t size() const {
        switch (m_type) {
            case JsonType::Object: return m_object.size();
            case JsonType::Array: return m_array.size();
            default: return 0;
        }
    }

    bool empty() const {
        switch (m_type) {
            case JsonType::Null: return true;
            case JsonType::Object: return m_object.empty();
            case JsonType::Array: return m_array.empty();
            default: return false;
        }
    }

    operator bool() const {
        return m_type == JsonType::Bool ? m_bool : false;
    }

    explicit operator int() const { return get<int>(); }
    explicit operator float() const { return get<float>(); }
    explicit operator double() const { return get<double>(); }

    auto begin() { return m_array.begin(); }
    auto end() { return m_array.end(); }
    auto begin() const { return m_array.begin(); }
    auto end() const { return m_array.end(); }

    DynamicTrackedString dumpSecure() const {
        std::string result;

        size_t estimated = estimateSerializedSize();
        result.reserve(estimated);
        dumpImpl(result);
        DynamicTrackedString secureResult(result);

        if (result.capacity() > 0) {
            SecureZeroMemory(result.data(), result.capacity());
        }
        return secureResult;
    }

    std::string dump() const {
        std::string result;
        result.reserve(4096);
        dumpImpl(result);
        return result;
    }

    static WhipJsonValue parse(const char* str) {
        if (!str) return WhipJsonValue();
        const char* ptr = str;
        return parseValue(ptr);
    }

    static WhipJsonValue parse(const std::string& str) {
        return parse(str.c_str());
    }

    static WhipJsonValue object() {
        WhipJsonValue val;
        val.m_type = JsonType::Object;
        return val;
    }

    static WhipJsonValue array() {
        WhipJsonValue val;
        val.m_type = JsonType::Array;
        return val;
    }

    void clear() {
        m_string.secureClear();

        for (auto& [key, val] : m_object) {
            key.secureClear();
            val.clear();
        }
        m_object.clear();

        for (auto& val : m_array) {
            val.clear();
        }
        m_array.clear();

        m_type = JsonType::Null;
        m_bool = false;
        m_int = 0;
        m_float = 0.0;
    }

private:
    JsonType m_type = JsonType::Null;
    bool m_bool = false;
    int64_t m_int = 0;
    double m_float = 0.0;
    DynamicTrackedString m_string;
    std::vector<std::pair<DynamicTrackedString, WhipJsonValue>> m_object;
    std::vector<WhipJsonValue> m_array;

    static const WhipJsonValue& nullValue() {
        static const WhipJsonValue s_null;
        return s_null;
    }

    size_t estimateSerializedSize() const {
        switch (m_type) {
            case JsonType::Null: return 4;
            case JsonType::Bool: return 5;
            case JsonType::Int: return 20;
            case JsonType::Float: return 24;
            case JsonType::String: return m_string.size() + 16;
            case JsonType::Array: {
                size_t est = 2;
                for (const auto& v : m_array) est += v.estimateSerializedSize() + 1;
                return est;
            }
            case JsonType::Object: {
                size_t est = 2;
                for (const auto& [k, v] : m_object)
                    est += k.size() + 4 + v.estimateSerializedSize() + 1;
                return est;
            }
        }
        return 16;
    }

    void dumpImpl(std::string& out) const {
        switch (m_type) {
            case JsonType::Null:
                out += "null";
                break;
            case JsonType::Bool:
                out += m_bool ? "true" : "false";
                break;
            case JsonType::Int: {
                char buf[32];
                snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(m_int));
                out += buf;
                break;
            }
            case JsonType::Float: {
                char buf[64];
                int n = snprintf(buf, sizeof(buf), "%.17g", m_float);
                out += buf;
                bool hasDot = false;
                for (int i = 0; i < n; i++) {
                    if (buf[i] == '.' || buf[i] == 'e' || buf[i] == 'E') {
                        hasDot = true;
                        break;
                    }
                }
                if (!hasDot) out += ".0";
                break;
            }
            case JsonType::String:
                out += '"';
                appendEscaped(out, m_string.c_str());
                out += '"';
                break;
            case JsonType::Array:
                out += '[';
                for (size_t i = 0; i < m_array.size(); i++) {
                    if (i > 0) out += ',';
                    m_array[i].dumpImpl(out);
                }
                out += ']';
                break;
            case JsonType::Object:
                out += '{';
                for (size_t i = 0; i < m_object.size(); i++) {
                    if (i > 0) out += ',';
                    out += '"';
                    appendEscaped(out, m_object[i].first.c_str());
                    out += '"';
                    out += ':';
                    m_object[i].second.dumpImpl(out);
                }
                out += '}';
                break;
        }
    }

    static void appendEscaped(std::string& out, const char* str) {
        if (!str) return;
        for (const char* p = str; *p; p++) {
            switch (*p) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(*p) < 0x20) {
                        char esc[8];
                        snprintf(esc, sizeof(esc), "\\u%04x", static_cast<unsigned char>(*p));
                        out += esc;
                    } else {
                        out += *p;
                    }
                    break;
            }
        }
    }

    static void skipWs(const char*& p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    }

    static WhipJsonValue parseValue(const char*& p) {
        skipWs(p);
        if (!*p) return WhipJsonValue();

        switch (*p) {
            case '{': return parseObj(p);
            case '[': return parseArr(p);
            case '"': {
                WhipJsonValue val;
                val.m_type = JsonType::String;
                val.m_string = parseStr(p);
                return val;
            }
            case 't':
                if (strncmp(p, "true", 4) == 0) { p += 4; return WhipJsonValue(true); }
                return WhipJsonValue();
            case 'f':
                if (strncmp(p, "false", 5) == 0) { p += 5; return WhipJsonValue(false); }
                return WhipJsonValue();
            case 'n':
                if (strncmp(p, "null", 4) == 0) { p += 4; return WhipJsonValue(); }
                return WhipJsonValue();
            default:
                if ((*p >= '0' && *p <= '9') || *p == '-')
                    return parseNum(p);
                return WhipJsonValue();
        }
    }

    static WhipJsonValue parseObj(const char*& p) {
        WhipJsonValue obj;
        obj.m_type = JsonType::Object;
        p++;
        skipWs(p);

        if (*p == '}') { p++; return obj; }

        while (*p) {
            skipWs(p);
            if (*p != '"') break;

            DynamicTrackedString key = parseStr(p);

            skipWs(p);
            if (*p == ':') p++;

            WhipJsonValue val = parseValue(p);
            obj.m_object.emplace_back(std::move(key), std::move(val));

            skipWs(p);
            if (*p == ',') { p++; continue; }
            if (*p == '}') { p++; break; }
            break;
        }

        return obj;
    }

    static WhipJsonValue parseArr(const char*& p) {
        WhipJsonValue arr;
        arr.m_type = JsonType::Array;
        p++;
        skipWs(p);

        if (*p == ']') { p++; return arr; }

        while (*p) {
            arr.m_array.push_back(parseValue(p));

            skipWs(p);
            if (*p == ',') { p++; continue; }
            if (*p == ']') { p++; break; }
            break;
        }

        return arr;
    }

    static DynamicTrackedString parseStr(const char*& p) {
        p++;

        const char* scan = p;
        size_t estimatedLen = 0;
        while (*scan && *scan != '"') {
            if (*scan == '\\' && *(scan + 1)) { scan += 2; estimatedLen += 2; }
            else { scan++; estimatedLen++; }
        }

        std::string tmp;
        tmp.reserve(estimatedLen);

        while (*p && *p != '"') {
            if (*p == '\\' && *(p + 1)) {
                p++;
                switch (*p) {
                    case '"':  tmp += '"'; break;
                    case '\\': tmp += '\\'; break;
                    case '/':  tmp += '/'; break;
                    case 'b':  tmp += '\b'; break;
                    case 'f':  tmp += '\f'; break;
                    case 'n':  tmp += '\n'; break;
                    case 'r':  tmp += '\r'; break;
                    case 't':  tmp += '\t'; break;
                    case 'u': {
                        if (p[1] && p[2] && p[3] && p[4]) {
                            char hex[5] = { p[1], p[2], p[3], p[4], 0 };
                            unsigned int cp = strtoul(hex, nullptr, 16);
                            if (cp < 0x80) {
                                tmp += static_cast<char>(cp);
                            } else if (cp < 0x800) {
                                tmp += static_cast<char>(0xC0 | (cp >> 6));
                                tmp += static_cast<char>(0x80 | (cp & 0x3F));
                            } else {
                                tmp += static_cast<char>(0xE0 | (cp >> 12));
                                tmp += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                                tmp += static_cast<char>(0x80 | (cp & 0x3F));
                            }
                            p += 4;
                        }
                        break;
                    }
                    default: tmp += *p; break;
                }
            } else {
                tmp += *p;
            }
            p++;
        }
        if (*p == '"') p++;

        DynamicTrackedString result(tmp);

        if (tmp.capacity() > 0) SecureZeroMemory(tmp.data(), tmp.capacity());
        return result;
    }

    static WhipJsonValue parseNum(const char*& p) {
        const char* start = p;
        if (*p == '-') p++;
        while (*p >= '0' && *p <= '9') p++;
        bool isFloat = false;
        if (*p == '.') { isFloat = true; p++; while (*p >= '0' && *p <= '9') p++; }
        if (*p == 'e' || *p == 'E') {
            isFloat = true; p++;
            if (*p == '+' || *p == '-') p++;
            while (*p >= '0' && *p <= '9') p++;
        }

        WhipJsonValue val;
        if (isFloat) {
            val.m_type = JsonType::Float;
            val.m_float = strtod(start, nullptr);
        } else {
            val.m_type = JsonType::Int;
            val.m_int = strtoll(start, nullptr, 10);
        }
        return val;
    }
};

enum TokenType {
    TOKEN_NONE,
    TOKEN_OBJECT_START,
    TOKEN_OBJECT_END,
    TOKEN_ARRAY_START,
    TOKEN_ARRAY_END,
    TOKEN_STRING,
    TOKEN_NUMBER,
    TOKEN_TRUE,
    TOKEN_FALSE,
    TOKEN_NULL,
    TOKEN_COLON,
    TOKEN_COMMA
};

struct Token {
    TokenType type;
    const char* start;
    int length;
};

class JsonParser {
private:
    const char* json;
    const char* ptr;
    Token current;

    inline void skipWhitespace() {
        while (*ptr == ' ' || *ptr == '\t' || *ptr == '\n' || *ptr == '\r') {
            ptr++;
        }
    }

    inline bool matchStr(const char* str, int len) const {
        return strncmp(ptr, str, len) == 0;
    }

    inline Token parseNumber() {
        Token tok;
        tok.type = TOKEN_NUMBER;
        tok.start = ptr;

        if (*ptr == '-') ptr++;
        while (*ptr >= '0' && *ptr <= '9') ptr++;
        if (*ptr == '.') {
            ptr++;
            while (*ptr >= '0' && *ptr <= '9') ptr++;
        }
        if (*ptr == 'e' || *ptr == 'E') {
            ptr++;
            if (*ptr == '+' || *ptr == '-') ptr++;
            while (*ptr >= '0' && *ptr <= '9') ptr++;
        }

        tok.length = static_cast<int>(ptr - tok.start);
        return tok;
    }

    inline Token parseString() {
        Token tok;
        tok.type = TOKEN_STRING;
        tok.start = ptr + 1;
        ptr++;

        while (*ptr != '"' && *ptr != '\0') {
            if (*ptr == '\\') ptr += 2;
            else ptr++;
        }

        tok.length = static_cast<int>(ptr - tok.start);
        if (*ptr == '"') ptr++;

        return tok;
    }

public:
    JsonParser(const char* jsonStr) : json(jsonStr), ptr(jsonStr), current{} {}

    Token next() {
        skipWhitespace();

        if (*ptr == '\0') {
            current.type = TOKEN_NONE;
            return current;
        }

        switch (*ptr) {
            case '{': current.type = TOKEN_OBJECT_START; current.start = ptr++; current.length = 1; break;
            case '}': current.type = TOKEN_OBJECT_END;   current.start = ptr++; current.length = 1; break;
            case '[': current.type = TOKEN_ARRAY_START;  current.start = ptr++; current.length = 1; break;
            case ']': current.type = TOKEN_ARRAY_END;    current.start = ptr++; current.length = 1; break;
            case ':': current.type = TOKEN_COLON;        current.start = ptr++; current.length = 1; break;
            case ',': current.type = TOKEN_COMMA;        current.start = ptr++; current.length = 1; break;
            case '"': current = parseString(); break;
            case 't':
                if (matchStr("true", 4)) { current.type = TOKEN_TRUE; current.start = ptr; current.length = 4; ptr += 4; }
                break;
            case 'f':
                if (matchStr("false", 5)) { current.type = TOKEN_FALSE; current.start = ptr; current.length = 5; ptr += 5; }
                break;
            case 'n':
                if (matchStr("null", 4)) { current.type = TOKEN_NULL; current.start = ptr; current.length = 4; ptr += 4; }
                break;
            default:
                if ((*ptr >= '0' && *ptr <= '9') || *ptr == '-') {
                    current = parseNumber();
                } else {
                    current.type = TOKEN_NONE;
                    ptr++;
                }
                break;
        }

        return current;
    }

    bool findKey(const char* key) {
        int keyLen = static_cast<int>(strlen(key));
        int depth = 0;

        while (true) {
            Token tok = next();
            if (tok.type == TOKEN_NONE) return false;
            if (tok.type == TOKEN_OBJECT_START) depth++;
            if (tok.type == TOKEN_OBJECT_END) {
                depth--;
                if (depth < 0) return false;
            }
            if (tok.type == TOKEN_STRING && depth == 0) {
                if (tok.length == keyLen && strncmp(tok.start, key, keyLen) == 0) {
                    next();
                    return true;
                }
            }
        }
    }

    bool getString(char* buffer, int maxLen) {
        Token tok = next();
        if (tok.type != TOKEN_STRING) return false;
        int len = tok.length < maxLen - 1 ? tok.length : maxLen - 1;
        strncpy(buffer, tok.start, len);
        buffer[len] = '\0';
        return true;
    }

    int getInt() {
        Token tok = next();
        if (tok.type != TOKEN_NUMBER) return 0;
        return atoi(tok.start);
    }

    bool getBool() {
        Token tok = next();
        return tok.type == TOKEN_TRUE;
    }

    char getChar() {
        Token tok = next();
        if (tok.type == TOKEN_TRUE) return 1;
        if (tok.type == TOKEN_FALSE) return 0;
        if (tok.type == TOKEN_NUMBER) return static_cast<char>(atoi(tok.start));
        return 0;
    }

    void reset() { ptr = json; }

    static bool isValid(const char* str) {
        if (!str || *str == '\0') return false;
        while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r') str++;
        return (*str == '{' || *str == '[');
    }
};

inline bool strEqual(const char* a, const char* b, int len) {
    return strncmp(a, b, len) == 0;
}

inline void strCopy(char* dest, const char* src, int len) {
    memcpy(dest, src, len);
    dest[len] = '\0';
}

}

#endif
