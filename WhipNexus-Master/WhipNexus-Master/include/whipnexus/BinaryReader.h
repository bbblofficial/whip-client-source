#ifndef WHIPNEXUS_BINARYREADER_H
#define WHIPNEXUS_BINARYREADER_H

#include "Types.h"

// Reader pour lire des paquets binaires
class BinaryReader {
private:
    const byte* data;
    u32 size;
    u32 position;

public:
    BinaryReader(const byte* data, u32 size);

    i32 readInt();
    i64 readLong();
    i16 readShort();
    bool readBool();
    void readFixedBytes(byte* output, u32 length);
    u32 readBytes(byte* output, u32 maxLength);
    u16 readString(char* output, u16 maxLength);

    u32 getPosition() const { return position; }
    u32 remaining() const { return size - position; }
    bool hasRemaining() const { return position < size; }

private:
    void checkRemaining(u32 needed);
};

#endif // WHIPNEXUS_BINARYREADER_H