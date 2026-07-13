#ifndef WHIPNEXUS_WHIPNEXUSSERVER_H
#define WHIPNEXUS_WHIPNEXUSSERVER_H

#include "Types.h"
#include "TcpServerSocket.h"
#include "CryptoService.h"
#include "PacketCodec.h"
#include "Packet.h"

// Handler de paquet côté serveur. opcode est neutre (u16).
typedef void (*ServerPacketHandler)(u32 clientId, u16 opcode, const byte* data, u32 length, void* userContext);
typedef void (*ServerClientDisconnectHandler)(u32 clientId, void* userContext);

struct ClientSession {
    u32 id;
    HANDLE socket;
    byte sendKey[32];
    byte recvKey[32];
    bool authenticated;   // Conservé pour compat ; non utilisé par Nexus, libre aux consommateurs.
    bool active;
    void* privateKey;
    byte publicKey[256];
    u32 publicKeyLength;
};

struct ServerHandlerEntry {
    u16 opcode;
    ServerPacketHandler handler;
    void* context;
    bool active;
};

struct ClientThreadParam {
    void* server;
    ClientSession* client;
};

class WhipNexusServer {
private:
    TcpServerSocket serverSocket;
    CryptoService crypto;
    PacketCodec codec;

    ClientSession* clients;
    i32 clientCount;
    i32 clientCapacity;
    u32 nextClientId;

    ServerHandlerEntry handlers[256];
    i32 handlerCount;

    void* acceptThread;
    void** clientThreads;
    i32 clientThreadCount;
    bool running;

    void* clientMutex;

    // Clé permanente du serveur pour certificate pinning.
    void* serverPermanentPrivateKey;
    byte serverPermanentPublicKey[256];
    u32 serverPermanentPublicKeyLength;

public:
    WhipNexusServer();
    ~WhipNexusServer();

    bool init();
    bool loadOrGeneratePermanentKey(const char* keyFilePath);
    bool bind(const char* host, u16 port);
    bool start();
    void stop();

    u16 getPort() const;
    bool isRunning() const { return running; }
    CryptoService& getCryptoService() { return crypto; }

    bool registerHandler(u16 opcode, ServerPacketHandler handler, void* context = nullptr);
    void unregisterHandler(u16 opcode);

    void setOnClientDisconnect(ServerClientDisconnectHandler handler, void* context = nullptr);

    bool sendToClient(u32 clientId, u16 opcode, const byte* data, u32 length);
    bool broadcastPacket(u16 opcode, const byte* data, u32 length);

    i32 getClientCount() const { return clientCount; }

private:
    static unsigned long WINAPI acceptThreadFunc(void* param);
    static unsigned long WINAPI clientThreadFunc(void* param);

    void acceptLoop();
    void clientLoop(ClientSession* client);

    bool performHandshakeServer(ClientSession* client);
    bool sendPacketToClient(ClientSession* client, const RawPacket& packet);
    bool receivePacketFromClient(ClientSession* client, RawPacket& packet);
    bool sendPlainPacketToClient(ClientSession* client, u16 opcode, const Buffer& payload);
    bool sendEncryptedPacketToClient(ClientSession* client, u16 opcode, const Buffer& payload);

    void dispatchPacket(u32 clientId, u16 opcode, const byte* data, u32 length);

    ClientSession* findClient(u32 clientId);
    void removeClient(u32 clientId);
    u32 addClient(HANDLE socket);

    ServerClientDisconnectHandler disconnectHandler;
    void* disconnectContext;
};

#endif // WHIPNEXUS_WHIPNEXUSSERVER_H
