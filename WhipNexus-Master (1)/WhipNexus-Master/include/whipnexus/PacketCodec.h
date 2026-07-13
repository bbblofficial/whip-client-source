#ifndef WHIPNEXUS_PACKETCODEC_H
#define WHIPNEXUS_PACKETCODEC_H

#include "Packet.h"
#include "BinaryWriter.h"
#include "BinaryReader.h"
#include "CryptoService.h"

// Encodeur/décodeur de paquets WHIP — couche transport uniquement.
// Ne connaît que :
//  - le RawPacket sur le fil (header + nonce + payload chiffré + HMAC)
//  - le handshake interne (CLIENT_HELLO / SERVER_HELLO)
//  - le wrap/unwrap chiffré (createEncryptedPacket / decryptPacket)
class PacketCodec {
private:
    CryptoService* crypto;

public:
    explicit PacketCodec(CryptoService* cryptoService);

    bool encodeRawPacket(const RawPacket& packet, Buffer& output);
    bool decodeRawPacket(const byte* data, u32 length, RawPacket& packet);

    bool encodeClientHello(const ClientHelloData& data, Buffer& payload);
    bool decodeClientHello(const byte* payload, u32 length, ClientHelloData& data);

    bool encodeServerHello(const ServerHelloData& data, Buffer& payload);
    bool decodeServerHello(const byte* payload, u32 length, ServerHelloData& data);

    // Wrap un payload en clair dans un RawPacket chiffré (AES-GCM + HMAC + padding).
    bool createEncryptedPacket(u16 opcode, const Buffer& plainPayload,
                               const byte* sessionKey, RawPacket& packet);

    // Vérifie HMAC + déchiffre AES-GCM. Le caller retire le padding s'il sait combien.
    bool decryptPacket(const RawPacket& packet, const byte* sessionKey, Buffer& plainPayload);
};

#endif // WHIPNEXUS_PACKETCODEC_H
