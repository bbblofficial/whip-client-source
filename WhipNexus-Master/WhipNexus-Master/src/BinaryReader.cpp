#pragma optimize("", off)
#include "whipnexus/BinaryReader.h"
#include "whipnexus/ProtocolConstants.h"
#include "whipnexus/SyscallManager.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

BinaryReader::BinaryReader(const byte* data, u32 size)
    : data(data), size(size), position(0) {
    VMProtectBeginUltra("BinaryReader_ctor");
    VMProtectEnd();
}

void BinaryReader::checkRemaining(u32 needed) {
    VMProtectBeginUltra("BinaryReader_checkRemaining");
    if (position + needed > size) {
        // Erreur: pas assez de données
        position = size;
    }
    VMProtectEnd();
}

i32 BinaryReader::readInt() {
    VMProtectBeginUltra("BinaryReader_readInt");
    checkRemaining(4);
    if (position + 4 > size) return 0;

    // Big-endian
    i32 value = ((i32)data[position] << 24) |
                ((i32)data[position + 1] << 16) |
                ((i32)data[position + 2] << 8) |
                ((i32)data[position + 3]);
    position += 4;
    return value;
    VMProtectEnd();
}

i64 BinaryReader::readLong() {
    VMProtectBeginUltra("BinaryReader_readLong");
    checkRemaining(8);
    if (position + 8 > size) return 0;

    // Big-endian
    i64 value = ((i64)data[position] << 56) |
                ((i64)data[position + 1] << 48) |
                ((i64)data[position + 2] << 40) |
                ((i64)data[position + 3] << 32) |
                ((i64)data[position + 4] << 24) |
                ((i64)data[position + 5] << 16) |
                ((i64)data[position + 6] << 8) |
                ((i64)data[position + 7]);
    position += 8;
    return value;
    VMProtectEnd();
}

i16 BinaryReader::readShort() {
    VMProtectBeginUltra("BinaryReader_readShort");
    checkRemaining(2);
    if (position + 2 > size) return 0;

    // Big-endian
    i16 value = ((i16)data[position] << 8) |
                ((i16)data[position + 1]);
    position += 2;
    return value;
    VMProtectEnd();
}

bool BinaryReader::readBool() {
    VMProtectBeginUltra("BinaryReader_readBool");
    checkRemaining(1);
    if (position + 1 > size) return false;

    return data[position++] != 0;
    VMProtectEnd();
}

void BinaryReader::readFixedBytes(byte* output, u32 length) {
    VMProtectBeginUltra("BinaryReader_readFixedBytes");
    checkRemaining(length);
    if (position + length > size) return;

    SyscallManager::SecureMemCpy(output, data + position, length);
    position += length;
    VMProtectEnd();
}

u32 BinaryReader::readBytes(byte* output, u32 maxLength) {
    VMProtectBeginUltra("BinaryReader_readBytes");
    i32 length = readInt();
    if (length < 0) return 0;

    u32 actualLength = (u32)length;
    if (actualLength > maxLength) {
        actualLength = maxLength;
    }

    checkRemaining(actualLength);
    if (position + actualLength > size) return 0;

    memcpy(output, data + position, actualLength);
    position += actualLength;
    return actualLength;
    VMProtectEnd();
}

u16 BinaryReader::readString(char* output, u16 maxLength) {
    VMProtectBeginUltra("BinaryReader_readString");
    i16 length = readShort();

    if (length < 0) {
        output[0] = '\0';
        return 0;
    }

    if (length > ProtocolConstants::MAX_STRING_LENGTH) {
        output[0] = '\0';
        return 0;
    }

    u16 actualLength = (u16)length;
    if (actualLength > maxLength - 1) {
        actualLength = maxLength - 1;
    }

    checkRemaining(actualLength);
    if (position + actualLength > size) {
        output[0] = '\0';
        return 0;
    }

    memcpy(output, data + position, actualLength);
    output[actualLength] = '\0';
    position += (u16)length;

    return actualLength;
    VMProtectEnd();
}