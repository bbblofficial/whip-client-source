#pragma once

#include <string>
#include "../../util/whipJson.h"

class ISetting;

enum class SettingType : int;

enum class CodecError {
    NONE = 0,
    INVALID_TYPE,
    MISSING_FIELD,
    VALIDATION_FAILED,
    DECODE_FAILED
};

struct CodecResult {
    bool success;
    CodecError error;
    std::string message;

    static CodecResult ok() {
        return {true, CodecError::NONE, ""};
    }

    static CodecResult fail(CodecError err, const std::string& msg) {
        return {false, err, msg};
    }
};

class ISettingCodec {
public:
    virtual ~ISettingCodec() = default;

    virtual whip::WhipJsonValue encode(const ISetting* setting) const = 0;

    virtual CodecResult decode(ISetting* setting, const whip::WhipJsonValue& data) const = 0;

    virtual CodecResult validate(const whip::WhipJsonValue& data) const = 0;

    virtual SettingType getType() const = 0;
};
