#ifndef WHIPNEXUS_PROTOCOLCONSTANTS_H
#define WHIPNEXUS_PROTOCOLCONSTANTS_H

#include "Types.h"

// Constantes du protocole WHIP (transport)
namespace ProtocolConstants
{
    extern const byte MAGIC[4];

    constexpr u16 VERSION = 1;
    constexpr u32 HEADER_SIZE = 24;
    constexpr u32 HMAC_SIZE = 32;
    constexpr u32 NONCE_SIZE = 12;
    constexpr u32 CLIENT_NONCE_SIZE = 32;
    constexpr u32 MAX_PAYLOAD_SIZE = 100 * 1024 * 1024;
    constexpr u32 MAX_PACKET_SIZE = HEADER_SIZE + MAX_PAYLOAD_SIZE + HMAC_SIZE;
    constexpr u16 MAX_STRING_LENGTH = 32767;

    constexpr u32 MIN_PADDING_SIZE = 16;
    constexpr u32 MAX_PADDING_SIZE = 64;

    // Opcodes réservés au handshake interne Nexus (jamais exposés aux consommateurs).
    constexpr u16 OPCODE_CLIENT_HELLO = 0x01;
    constexpr u16 OPCODE_SERVER_HELLO = 0x02;
}

#endif // WHIPNEXUS_PROTOCOLCONSTANTS_H
