#ifndef WHIPNEXUS_WHIPNEXUS_H
#define WHIPNEXUS_WHIPNEXUS_H

#include "Types.h"
#include "TlsSocket.h"
#include "CryptoService.h"
#include "PacketCodec.h"
#include "Packet.h"

// Handler appelé pour chaque paquet entrant après déchiffrement.
// L'opcode est neutre (u16) — Nexus ne connaît pas la sémantique métier.
typedef void (*PacketHandler)(u16 opcode, const byte* data, u32 length, void* userContext);

struct HandlerEntry {
    u16 opcode;
    PacketHandler handler;
    void* context;
    bool active;
};

// Client WhipNexus — couche transport chiffrée façon Netty.
// Responsabilités :
//  - TCP via syscalls AFD
//  - TLS 1.3/1.2 maison (optionnel, désactivable via setPlainMode)
//  - Handshake WHIP : ECDH P-256 éphémère + certificate pinning ECDSA
//  - AES-256-GCM + HMAC-SHA256 par paquet, avec padding aléatoire
//  - Anti-rejeu nonce (ring buffer 256 entrées)
//  - Boucle d'événements + dispatch par opcode
// Aucune connaissance des protocoles applicatifs (auth, fichiers, configs, IPC) :
// les consommateurs sérialisent leurs payloads et appellent sendPacket(opcode, ...).
class WhipNexus {
private:
    TlsSocket socket;
    CryptoService crypto;
    PacketCodec codec;

    // Clés de session dérivées via ECDH
    byte sendKey[32];
    byte recvKey[32];
    byte sessionKey[32];

    // Clés éphémères pour ECDH
    void* clientPrivateKey;
    byte clientPublicKey[256];
    u32 clientPublicKeyLength;

    // Handlers par opcode
    HandlerEntry handlers[256];
    i32 handlerCount;

    // Boucle d'événements
    void* eventThread;
    bool running;
    bool connected;
    // Proof of a real handshake: 32-bit fingerprint of sessionKey, mixed
    // through SplitMix64. Zero before connect(), proof-of-real-handshake
    // after. A reverser patching connect() to RET-true early leaves
    // sessionKey zeroed → proof mismatch in isConnected().
    u64 connectedProof;
    // Third tamper layer: WhipVM-encoded `connected` state. 0 décodé =
    // connected, sinon non. Patch isolé du bool ou du proof ne suffit pas —
    // il faut aussi reproduire la cascade dérivée de vm_runtime_key_stable().
    // Encode/decode dans WhipNexus.cpp (vm_cpp.hpp ne fuit pas dans le header).
    u64 connectedVmEncoded;

    // Mutex envoi (sérialise sendPacket)
    void* sendMutex;
    // Mutex IO (request-response atomique exposé via lockIO/unlockIO)
    void* ioMutex;

    i32 lastErrorCode;

    // Anti-rejeu nonce client
    static const i32 NONCE_HISTORY_SIZE = 256;
    byte nonceHistory[256][12];
    i32 nonceHistoryIndex;
    i32 nonceHistoryCount;
    bool isNonceReplay(const byte* nonce);

    // Certificate pinning. The bool is the "user intent" flag set by
    // setCertificatePinning(); `pinningProof` is a SplitMix64 fingerprint
    // bound to the hash bytes. A reverser flipping the bool to false in
    // memory leaves the proof matching the previous (true + hash) state →
    // performHandshake() detects the tamper and runs the cert check anyway.
    bool certificatePinningEnabled;
    u64  pinningProof;
    byte pinnedCertificateHash[32];

public:
    WhipNexus();
    ~WhipNexus();

    bool init();

    // Mode plain (TCP brut, pas de TLS) — pour IPC localhost.
    void setPlainMode(bool enabled);

    // Épingle le SHA-256 de la clé permanente serveur. Doit être appelé avant connect().
    void setCertificatePinning(bool enabled, const byte* certHash);

    // Connexion + TLS + handshake WHIP en une seule étape.
    bool connect(const char* host, u16 port);
    void disconnect();

    // Out-of-line: cross-checks `connected` against `connectedProof`. A
    // reverser patching `connected = true` directly is caught because
    // connectedProof still encodes the zero-key state. Defined in WhipNexus.cpp.
    bool isConnected() const;

    bool registerHandler(u16 opcode, PacketHandler handler, void* context = nullptr);
    void unregisterHandler(u16 opcode);

    bool startEventLoop();
    void stopEventLoop();
    bool isEventLoopRunning() const { return running; }

    // IO mutex pour cycles request-response atomiques (côté appelant).
    void lockIO();
    void unlockIO();

    // Envoi chiffré thread-safe. opcode est passé tel quel sur le fil.
    bool sendPacket(u16 opcode, const byte* data, u32 length);

    // Réception synchrone d'un paquet déjà déchiffré (utilisée par les flows
    // request-response côté appelant ; pour le mode événements, registerHandler suffit).
    bool receiveDecryptedPacket(u16& opcodeOut, byte* dataOut, u32* dataLenOut, u32 maxLen);

    // Helpers crypto exposés (BCrypt) pour les consommateurs qui en ont besoin.
    bool generateRandomBytes(byte* output, u32 length);
    bool computeHmac(const byte* data, u32 dataLength, byte* hmacOut);

    // AES-256-GCM décryption avec la sessionKey HKDF-dérivée.
    // Utilisé par les flows de fichiers chunked où chaque chunk est ré-encrypté
    // au-dessus du transport WHIP : le serveur émet `nonce(12) || ciphertext+tag`
    // dans le payload du paquet, et le consommateur doit faire un second pass de
    // décryption avec sessionKey après que receiveDecryptedPacket ait dépouillé
    // la couche WHIP.
    //   nonce            : 12 bytes (IV AES-GCM côté serveur)
    //   ciphertextWithTag: ciphertext suivi du tag GCM 16 bytes
    //   plaintextOut     : buffer de sortie, doit être ≥ ciphertextLen - 16
    //   plaintextLenOut  : longueur réelle écrite (= ciphertextLen - 16 si succès)
    bool decryptFilePayload(const byte* nonce, u32 nonceLen,
                            const byte* ciphertextWithTag, u32 ciphertextLen,
                            byte* plaintextOut, u32* plaintextLenOut);

    i32 getLastErrorCode() const { return lastErrorCode; }

private:
    bool performHandshake();
    bool sendPacketInternal(const RawPacket& packet);
    bool receivePacket(RawPacket& packet);
    bool sendPlainPacket(u16 opcode, const Buffer& payload);
    bool sendEncryptedPacket(u16 opcode, const Buffer& payload);

    static unsigned long WINAPI eventLoopThreadFunc(void* param);
    void eventLoopRun();

public:
    // Dispatcher exposé (utile aux consommateurs qui pompent eux-mêmes les paquets).
    void dispatchPacket(u16 opcode, const byte* data, u32 length);
};

#endif // WHIPNEXUS_WHIPNEXUS_H
