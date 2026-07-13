#pragma optimize("", off)
#include "whipnexus/BinaryWriter.h"
#include "whipnexus/ProtocolConstants.h"
#include "whipnexus/SyscallManager.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

BinaryWriter::BinaryWriter() : buffer(256), position(0) {
    VMProtectBeginUltra("BinaryWriter_ctor");
    VMProtectEnd();
}

BinaryWriter::BinaryWriter(u32 initialCapacity) : buffer(initialCapacity), position(0) {
    VMProtectBeginUltra("BinaryWriter_ctor_capacity");
    VMProtectEnd();
}

void BinaryWriter::ensureCapacity(u32 needed) {
    VMProtectBeginUltra("BinaryWriter_ensureCapacity");
    if (position + needed > buffer.capacity) {
        buffer.resize(position + needed);
    }
    VMProtectEnd();
}

void BinaryWriter::writeInt(i32 value) {
    VMProtectBeginUltra("BinaryWriter_writeInt");
    ensureCapacity(4);
    // Big-endian (network byte order)
    buffer.data[position++] = (byte)((value >> 24) & 0xFF);
    buffer.data[position++] = (byte)((value >> 16) & 0xFF);
    buffer.data[position++] = (byte)((value >> 8) & 0xFF);
    buffer.data[position++] = (byte)(value & 0xFF);
    VMProtectEnd();
}

void BinaryWriter::writeLong(i64 value) {
    VMProtectBeginUltra("BinaryWriter_writeLong");
    ensureCapacity(8);
    // Big-endian
    buffer.data[position++] = (byte)((value >> 56) & 0xFF);
    buffer.data[position++] = (byte)((value >> 48) & 0xFF);
    buffer.data[position++] = (byte)((value >> 40) & 0xFF);
    buffer.data[position++] = (byte)((value >> 32) & 0xFF);
    buffer.data[position++] = (byte)((value >> 24) & 0xFF);
    buffer.data[position++] = (byte)((value >> 16) & 0xFF);
    buffer.data[position++] = (byte)((value >> 8) & 0xFF);
    buffer.data[position++] = (byte)(value & 0xFF);
    VMProtectEnd();
}

void BinaryWriter::writeShort(i16 value) {
    VMProtectBeginUltra("BinaryWriter_writeShort");
    ensureCapacity(2);
    // Big-endian
    buffer.data[position++] = (byte)((value >> 8) & 0xFF);
    buffer.data[position++] = (byte)(value & 0xFF);
    VMProtectEnd();
}

void BinaryWriter::writeBool(bool value) {
    VMProtectBeginUltra("BinaryWriter_writeBool");
    ensureCapacity(1);
    buffer.data[position++] = value ? 1 : 0;
    VMProtectEnd();
}

void BinaryWriter::writeBytes(const byte* data, u32 length) {
    VMProtectBeginUltra("BinaryWriter_writeBytes");
    ensureCapacity(length);
    SyscallManager::SecureMemCpy(buffer.data + position, data, length);
    position += length;
    VMProtectEnd();
}

void BinaryWriter::writeFixedBytes(const byte* data, u32 length) {
    VMProtectBeginUltra("BinaryWriter_writeFixedBytes");
    writeBytes(data, length);
    VMProtectEnd();
}

void BinaryWriter::writeLengthPrefixedBytes(const byte* data, u32 length) {
    VMProtectBeginUltra("BinaryWriter_writeLengthPrefixedBytes");
    writeInt((i32)length);
    writeBytes(data, length);
    VMProtectEnd();
}

void BinaryWriter::writeString(const char* str) {
    VMProtectBeginUltra("BinaryWriter_writeString");
    if (str == nullptr) {
        writeShort(-1);
        return;
    }

    u16 length = (u16)SyscallManager::StrLen(str);
    if (length > ProtocolConstants::MAX_STRING_LENGTH) {
        length = ProtocolConstants::MAX_STRING_LENGTH;
    }

    writeShort((i16)length);
    if (length > 0) {
        writeBytes((const byte*)str, length);
    }
    VMProtectEnd();
}

void BinaryWriter::reset() {
    VMProtectBeginUltra("BinaryWriter_reset");
    position = 0;
    VMProtectEnd();
}