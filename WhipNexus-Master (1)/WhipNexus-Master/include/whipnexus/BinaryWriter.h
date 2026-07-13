#ifndef WHIPNEXUS_BINARYWRITER_H
#define WHIPNEXUS_BINARYWRITER_H

#include "Types.h"

// Writer pour construire des paquets binaires
class BinaryWriter {
private:
    Buffer buffer;
    u32 position;

public:
    BinaryWriter();
    explicit BinaryWriter(u32 initialCapacity);

    void writeInt(i32 value);
    void writeLong(i64 value);
    void writeShort(i16 value);
    void writeBool(bool value);
    void writeBytes(const byte* data, u32 length);
    void writeFixedBytes(const byte* data, u32 length);
    void writeLengthPrefixedBytes(const byte* data, u32 length);
    void writeString(const char* str);

    const byte* getData() const { return buffer.data; }
    u32 getSize() const { return position; }

    void reset();

private:
    void ensureCapacity(u32 needed);
};

#endif // WHIPNEXUS_BINARYWRITER_H