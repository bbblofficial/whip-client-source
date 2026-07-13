#ifndef WHIPNEXUS_PACKET_H
#define WHIPNEXUS_PACKET_H

#include "Types.h"
#include "ProtocolConstants.h"

// Paquet brut (avant/après chiffrement). L'opcode est neutre (u16) :
// Nexus ne connaît pas la sémantique métier des opcodes, il les transporte tels quels.
struct RawPacket {
    u16 opcode;
    byte nonce[ProtocolConstants::NONCE_SIZE];
    Buffer payload;
    byte hmac[ProtocolConstants::HMAC_SIZE];

    RawPacket();
    ~RawPacket();

    void clear();
};

// Données du handshake interne Nexus (CLIENT_HELLO).
struct ClientHelloData {
    i32 version;
    byte clientNonce[ProtocolConstants::CLIENT_NONCE_SIZE];
    byte* clientPublicKey;
    u32 clientPublicKeyLength;

    ClientHelloData();
    ~ClientHelloData();
};

// Données du handshake interne Nexus (SERVER_HELLO).
struct ServerHelloData {
    byte serverNonce[32];
    char tempSessionId[65];
    byte* serverPublicKey;
    u32 serverPublicKeyLength;
    byte* serverPermanentPublicKey;
    u32 serverPermanentPublicKeyLength;
    byte* signature;
    u32 signatureLength;

    ServerHelloData();
    ~ServerHelloData();
};

#endif // WHIPNEXUS_PACKET_H
