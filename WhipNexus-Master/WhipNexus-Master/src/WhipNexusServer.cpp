#pragma optimize("", off)
#include "whipnexus/WhipNexusServer.h"
#include "whipnexus/SyscallManager.h"
#include "whipsyscall/AfdSocket.h"
#include "whipsyscall/SyscallInvoker.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

WhipNexusServer::WhipNexusServer()
    : clients(nullptr), clientCount(0), clientCapacity(0), nextClientId(1),
      handlerCount(0), acceptThread(nullptr), clientThreads(nullptr),
      clientThreadCount(0), running(false), clientMutex(nullptr), codec(&crypto),
      serverPermanentPrivateKey(nullptr), serverPermanentPublicKeyLength(0),
      disconnectHandler(nullptr), disconnectContext(nullptr) {
    VMProtectBeginUltra("WhipNexusServer_ctor");
    SyscallManager::SecureMemSet(handlers, 0, sizeof(handlers));
    SyscallManager::SecureMemSet(serverPermanentPublicKey, 0, sizeof(serverPermanentPublicKey));
    VMProtectEnd();
}

WhipNexusServer::~WhipNexusServer() {
    VMProtectBeginUltra("WhipNexusServer_dtor");
    stop();
    if (serverPermanentPrivateKey) {
        crypto.freeKeyHandle(serverPermanentPrivateKey);
        serverPermanentPrivateKey = nullptr;
    }
    if (clients) {
        SyscallManager::GetWrappers()->HeapFree(clients);
    }
    if (clientThreads) {
        SyscallManager::GetWrappers()->HeapFree(clientThreads);
    }
    if (clientMutex) {
        DeleteCriticalSection((CRITICAL_SECTION*)clientMutex);
        SyscallManager::GetWrappers()->HeapFree(clientMutex);
    }
    VMProtectEnd();
}

bool WhipNexusServer::init() {
    VMProtectBeginUltra("WhipNexusServer_init");
    if (!SyscallManager::Init()) {
        return false;
        return false;
    }

    if (!crypto.init()) {
        return false;
    }

    clientCapacity = 16;
    clients = (ClientSession*)SyscallManager::GetWrappers()->HeapAlloc(sizeof(ClientSession) * clientCapacity);
    if (!clients) {
        return false;
    }
    SyscallManager::SecureMemSet(clients, 0, sizeof(ClientSession) * clientCapacity);

    clientThreads = (void**)SyscallManager::GetWrappers()->HeapAlloc(sizeof(void*) * clientCapacity);
    if (!clientThreads) {
        return false;
    }
    SyscallManager::SecureMemSet(clientThreads, 0, sizeof(void*) * clientCapacity);

    clientMutex = SyscallManager::GetWrappers()->HeapAlloc(sizeof(CRITICAL_SECTION));
    if (!clientMutex) {
        return false;
    }
    InitializeCriticalSection((CRITICAL_SECTION*)clientMutex);

    return true;
    VMProtectEnd();
}

// Convertir un chemin char* en NT wide path (\??\C:\...) pour NtCreateFile
// Retourne la longueur en WCHARs (sans le null terminator), 0 si erreur
static u32 toNtWidePath(const char* path, WORD* wideOut, u32 wideOutCapacity) {
    VMProtectBeginUltra("toNtWidePath");
    // Préfixe NT: \??\  (4 chars)
    const WORD prefix[] = { L'\\', L'?', L'?', L'\\' };
    const u32 prefixLen = 4;

    u32 pathLen = 0;
    while (path[pathLen]) pathLen++;

    if (prefixLen + pathLen + 1 > wideOutCapacity) { return 0; }

    for (u32 i = 0; i < prefixLen; i++) wideOut[i] = prefix[i];
    for (u32 i = 0; i < pathLen; i++) wideOut[prefixLen + i] = (WORD)(unsigned char)path[i];
    wideOut[prefixLen + pathLen] = 0;

    return prefixLen + pathLen;
    VMProtectEnd();
}

// Taille du blob ECDSA P-256 private: Magic(4) + cbKey(4) + X(32) + Y(32) + d(32) = 104
static const u32 ECDSA_P256_PRIVATE_BLOB_SIZE = 104;

bool WhipNexusServer::loadOrGeneratePermanentKey(const char* keyFilePath) {
    VMProtectBeginUltra("WhipNexusServer_loadOrGeneratePermanentKey");
    if (!keyFilePath) {
        // Pas de fichier spécifié, générer une clé éphémère (ancien comportement)
        bool result = crypto.generateEcdsaKeyPair(serverPermanentPublicKey, &serverPermanentPublicKeyLength, &serverPermanentPrivateKey);
        return result;
    }

    auto* wrappers = SyscallManager::GetWrappers();

    // Convertir le chemin en NT wide path
    WORD widePath[512];
    if (toNtWidePath(keyFilePath, widePath, 512) == 0) { return false; }

    // Tenter de charger la clé depuis le fichier
    // FILE_OPEN (0x01) = ouvrir seulement si existe
    HANDLE hFile = wrappers->CreateFile(widePath,
        0x80000000 | 0x00100000,  // GENERIC_READ | SYNCHRONIZE
        0x01,                      // FILE_SHARE_READ
        0x01);                     // FILE_OPEN (fail si n'existe pas)

    if (hFile) {
        byte blob[ECDSA_P256_PRIVATE_BLOB_SIZE];
        DWORD bytesRead = 0;

        bool readOk = wrappers->ReadFile(hFile, blob, ECDSA_P256_PRIVATE_BLOB_SIZE, &bytesRead);
        wrappers->CloseHandle(hFile);

        if (readOk && bytesRead == ECDSA_P256_PRIVATE_BLOB_SIZE) {
            bool imported = crypto.importEcdsaKeyPair(blob, bytesRead,
                serverPermanentPublicKey, &serverPermanentPublicKeyLength, &serverPermanentPrivateKey);
            SyscallManager::SecureZero(blob, sizeof(blob));

            if (imported) { return true; }
        }

        SyscallManager::SecureZero(blob, sizeof(blob));
        // Fichier corrompu ou invalide, on régénère
    }

    // Générer une nouvelle paire de clés
    if (!crypto.generateEcdsaKeyPair(serverPermanentPublicKey, &serverPermanentPublicKeyLength, &serverPermanentPrivateKey)) {
        return false;
    }

    // Exporter et sauvegarder la clé privée
    byte blob[ECDSA_P256_PRIVATE_BLOB_SIZE];
    u32 blobLen = 0;

    if (!crypto.exportEcdsaPrivateKey(serverPermanentPrivateKey, blob, sizeof(blob), &blobLen)) {
        SyscallManager::SecureZero(blob, sizeof(blob));
        return true; // Clé générée mais pas persistée — fonctionnel mais pas idéal
    }

    // FILE_CREATE (0x02) = créer nouveau fichier (échoue si existe déjà)
    // FILE_OPEN_IF (0x03) = ouvrir si existe, créer sinon
    HANDLE hWriteFile = wrappers->CreateFile(widePath,
        0x40000000 | 0x00100000,  // GENERIC_WRITE | SYNCHRONIZE
        0x00,                      // Pas de partage en écriture
        0x02);                     // FILE_CREATE

    if (hWriteFile) {
        DWORD bytesWritten = 0;
        wrappers->WriteFile(hWriteFile, blob, blobLen, &bytesWritten);
        wrappers->CloseHandle(hWriteFile);
    }

    SyscallManager::SecureZero(blob, sizeof(blob));
    return true;
    VMProtectEnd();
}

bool WhipNexusServer::bind(const char* host, u16 port) {
    VMProtectBeginUltra("WhipNexusServer_bind");
    bool result = serverSocket.bind(host, port);
    return result;
    VMProtectEnd();
}

bool WhipNexusServer::start() {
    VMProtectBeginUltra("WhipNexusServer_start");
    if (!serverSocket.listen()) {
        return false;
    }

    running = true;
    acceptThread = CreateThread(nullptr, 0, acceptThreadFunc, this, 0, nullptr);
    bool result = acceptThread != nullptr;
    return result;
    VMProtectEnd();
}

void WhipNexusServer::stop() {
    VMProtectBeginUltra("WhipNexusServer_stop");
    if (!running) { return; }

    running = false;

    SyscallResolver* res = SyscallManager::GetResolver();

    // Cancel ALL I/O operations first to unblock threads immediately
    WORD ssn;
    PVOID addr;
    if (res->ResolveByName("NtCancelIoFile", ssn, addr)) {
        IO_STATUS_BLOCK ioStatus = { 0 };

        // Cancel server socket I/O
        if (serverSocket.isListening()) {
            // Need to access the internal handle - we'll just close it
        }

        // Cancel all client socket I/O
        EnterCriticalSection((CRITICAL_SECTION*)clientMutex);
        for (i32 i = 0; i < clientCount; i++) {
            if (clients[i].active && clients[i].socket) {
                SyscallInvoker::Invoke(ssn, clients[i].socket, &ioStatus);
            }
        }
        LeaveCriticalSection((CRITICAL_SECTION*)clientMutex);
    }

    // Close server socket
    serverSocket.close();

    // Close ALL client sockets
    EnterCriticalSection((CRITICAL_SECTION*)clientMutex);
    for (i32 i = 0; i < clientCount; i++) {
        if (clients[i].active) {
            AfdSocket::Close(res, clients[i].socket);
            clients[i].socket = nullptr;
            clients[i].active = false;
        }
    }
    LeaveCriticalSection((CRITICAL_SECTION*)clientMutex);

    // Force terminate threads immediately
    if (acceptThread) {
        TerminateThread(acceptThread, 0);
        CloseHandle(acceptThread);
        acceptThread = nullptr;
    }

    for (i32 i = 0; i < clientThreadCount; i++) {
        if (clientThreads[i]) {
            TerminateThread(clientThreads[i], 0);
            CloseHandle(clientThreads[i]);
            clientThreads[i] = nullptr;
        }
    }
    clientThreadCount = 0;

    VMProtectEnd();
}

u16 WhipNexusServer::getPort() const {
    VMProtectBeginUltra("WhipNexusServer_getPort");
    u16 result = serverSocket.getPort();
    return result;
    VMProtectEnd();
}

bool WhipNexusServer::registerHandler(u16 opcode, ServerPacketHandler handler, void* context) {
    VMProtectBeginUltra("WhipNexusServer_registerHandler");
    if (handlerCount >= 256) { return false; }

    for (i32 i = 0; i < handlerCount; i++) {
        if (handlers[i].opcode == opcode) {
            handlers[i].handler = handler;
            handlers[i].context = context;
            handlers[i].active = true;
            return true;
        }
    }

    handlers[handlerCount].opcode = opcode;
    handlers[handlerCount].handler = handler;
    handlers[handlerCount].context = context;
    handlers[handlerCount].active = true;
    handlerCount++;
    return true;
    VMProtectEnd();
}

void WhipNexusServer::setOnClientDisconnect(ServerClientDisconnectHandler handler, void* context) {
    VMProtectBeginUltra("WhipNexusServer_setOnClientDisconnect");
    disconnectHandler = handler;
    disconnectContext = context;
    VMProtectEnd();
}

void WhipNexusServer::unregisterHandler(u16 opcode) {
    VMProtectBeginUltra("WhipNexusServer_unregisterHandler");
    for (i32 i = 0; i < handlerCount; i++) {
        if (handlers[i].opcode == opcode) {
            handlers[i].active = false;
            return;
        }
    }
    VMProtectEnd();
}

unsigned long WINAPI WhipNexusServer::acceptThreadFunc(void* param) {
    VMProtectBeginUltra("WhipNexusServer_acceptThreadFunc");
    auto* server = (WhipNexusServer*)param;
    server->acceptLoop();
    return 0;
    VMProtectEnd();
}

void WhipNexusServer::acceptLoop() {
    while (running) {
        HANDLE clientSock = serverSocket.accept();
        if (!clientSock) {
            if (!running) break;
            continue;
        }

        u32 clientId = addClient(clientSock);
        ClientSession* client = findClient(clientId);
        if (!client) {
            AfdSocket::Close(SyscallManager::GetResolver(), clientSock);
            continue;
        }

        if (!performHandshakeServer(client)) {
            removeClient(clientId);
            continue;
        }

        auto* param = (ClientThreadParam*)SyscallManager::GetWrappers()->HeapAlloc(sizeof(ClientThreadParam));
        if (!param) {
            removeClient(clientId);
            continue;
        }
        param->server = this;
        param->client = client;

        void* thread = CreateThread(nullptr, 0, clientThreadFunc, param, 0, nullptr);
        if (thread) {
            if (clientThreadCount < clientCapacity) {
                clientThreads[clientThreadCount++] = thread;
            }
        } else {
            SyscallManager::GetWrappers()->HeapFree(param);
            removeClient(clientId);
        }
    }
}

unsigned long WINAPI WhipNexusServer::clientThreadFunc(void* param) {
    VMProtectBeginUltra("WhipNexusServer_clientThreadFunc");
    auto* p = (ClientThreadParam*)param;
    auto* server = (WhipNexusServer*)p->server;
    auto* client = p->client;
    SyscallManager::GetWrappers()->HeapFree(p);
    server->clientLoop(client);
    return 0;
    VMProtectEnd();
}

void WhipNexusServer::clientLoop(ClientSession* client) {
    VMProtectBeginUltra("WhipNexusServer_clientLoop");
    u32 clientId = client->id;

    while (running && client->active) {
        RawPacket packet;
        if (!receivePacketFromClient(client, packet)) {
            break;
        }

        Buffer plainPayload;
        if (!codec.decryptPacket(packet, client->recvKey, plainPayload)) {
            break;
        }

        dispatchPacket(client->id, packet.opcode, plainPayload.data, plainPayload.size);

        plainPayload.clear();
        packet.clear();
    }
    removeClient(clientId);

    if (disconnectHandler) {
        disconnectHandler(clientId, disconnectContext);
    }
    VMProtectEnd();
}

bool WhipNexusServer::performHandshakeServer(ClientSession* client) {
    VMProtectBeginUltra("WhipNexusServer_performHandshakeServer");

    RawPacket clientHello;
    if (!receivePacketFromClient(client, clientHello)) {
        return false;
    }

    if (clientHello.opcode != ProtocolConstants::OPCODE_CLIENT_HELLO) {
        return false;
    }

    ClientHelloData chData;
    if (!codec.decodeClientHello(clientHello.payload.data, clientHello.payload.size, chData)) {
        return false;
    }

    if (!crypto.generateEcdhKeyPair(client->publicKey, &client->publicKeyLength, &client->privateKey)) {
        return false;
    }

    ServerHelloData shData;
    crypto.generateRandomBytes(shData.serverNonce, 32);
    for (i32 i = 0; i < 32; i++) {
        byte b = shData.serverNonce[i];
        shData.tempSessionId[i * 2] = "0123456789abcdef"[(b >> 4) & 0x0F];
        shData.tempSessionId[i * 2 + 1] = "0123456789abcdef"[b & 0x0F];
    }
    shData.tempSessionId[64] = '\0';
    shData.serverPublicKey = client->publicKey;
    shData.serverPublicKeyLength = client->publicKeyLength;

    shData.serverPermanentPublicKey = serverPermanentPublicKey;
    shData.serverPermanentPublicKeyLength = serverPermanentPublicKeyLength;

    byte signature[256];
    u32 signatureLength = 0;
    if (serverPermanentPrivateKey && serverPermanentPublicKeyLength > 0) {
        if (!crypto.signEcdsa(serverPermanentPrivateKey, client->publicKey, client->publicKeyLength, signature, &signatureLength)) {
            return false;
        }
        shData.signature = signature;
        shData.signatureLength = signatureLength;
    } else {
        shData.signature = nullptr;
        shData.signatureLength = 0;
    }

    Buffer shPayload;
    if (!codec.encodeServerHello(shData, shPayload)) {
        return false;
    }

    shData.serverPublicKey = nullptr;
    shData.serverPublicKeyLength = 0;
    shData.serverPermanentPublicKey = nullptr;
    shData.serverPermanentPublicKeyLength = 0;
    shData.signature = nullptr;
    shData.signatureLength = 0;

    if (!sendPlainPacketToClient(client, ProtocolConstants::OPCODE_SERVER_HELLO, shPayload)) {
        shPayload.clear();
        return false;
    }
    shPayload.clear();

    byte sharedSecret[32];
    if (!crypto.deriveSessionKey(client->privateKey, chData.clientPublicKey, chData.clientPublicKeyLength,
                                  chData.clientNonce, shData.serverNonce, sharedSecret)) {
        return false;
    }

    SyscallManager::SecureMemCpy(client->sendKey, sharedSecret, 32);
    SyscallManager::SecureMemCpy(client->recvKey, sharedSecret, 32);
    SyscallManager::SecureZero(sharedSecret, 32);
    return true;
    VMProtectEnd();
}

bool WhipNexusServer::sendPacketToClient(ClientSession* client, const RawPacket& packet) {
    VMProtectBeginUltra("WhipNexusServer_sendPacketToClient");

    Buffer encoded;
    if (!codec.encodeRawPacket(packet, encoded)) {
        return false;
    }

    SyscallResolver* res = SyscallManager::GetResolver();
    u32 totalSent = 0;
    while (totalSent < encoded.size) {
        ULONG sent = 0;
        if (!AfdSocket::Send(res, client->socket,
                             encoded.data + totalSent, encoded.size - totalSent, sent)) {
            encoded.clear();
            return false;
        }
        totalSent += sent;
    }

    encoded.clear();
    return true;
    VMProtectEnd();
}

bool WhipNexusServer::receivePacketFromClient(ClientSession* client, RawPacket& packet) {
    VMProtectBeginUltra("WhipNexusServer_receivePacketFromClient");

    SyscallResolver* res = SyscallManager::GetResolver();
    byte header[ProtocolConstants::HEADER_SIZE];
    u32 totalRead = 0;

    while (totalRead < ProtocolConstants::HEADER_SIZE) {
        ULONG received = 0;
        if (!AfdSocket::Recv(res, client->socket,
                             header + totalRead,
                             ProtocolConstants::HEADER_SIZE - totalRead, received)
            || received == 0) {
            return false;
        }
        totalRead += received;
    }

    if (SyscallManager::SecureMemCmp(header, ProtocolConstants::MAGIC, 4) != 0) {
        return false;
    }

    u32 payloadLength = (header[8] << 24) | (header[9] << 16) | (header[10] << 8) | header[11];

    u32 totalPacketSize = ProtocolConstants::HEADER_SIZE + payloadLength + ProtocolConstants::HMAC_SIZE;
    byte* fullPacket = (byte*)SyscallManager::GetWrappers()->HeapAlloc(totalPacketSize);
    if (!fullPacket) {
        return false;
    }

    SyscallManager::SecureMemCpy(fullPacket, header, ProtocolConstants::HEADER_SIZE);

    totalRead = 0;
    u32 remaining = payloadLength + ProtocolConstants::HMAC_SIZE;
    while (totalRead < remaining) {
        ULONG received = 0;
        if (!AfdSocket::Recv(res, client->socket,
                             fullPacket + ProtocolConstants::HEADER_SIZE + totalRead,
                             remaining - totalRead, received)
            || received == 0) {
            SyscallManager::GetWrappers()->HeapFree(fullPacket);
            return false;
        }
        totalRead += received;
    }

    bool result = codec.decodeRawPacket(fullPacket, totalPacketSize, packet);

    SyscallManager::GetWrappers()->HeapFree(fullPacket);
    return result;
    VMProtectEnd();
}

bool WhipNexusServer::sendPlainPacketToClient(ClientSession* client, u16 opcode, const Buffer& payload) {
    VMProtectBeginUltra("WhipNexusServer_sendPlainPacketToClient");
    RawPacket packet;
    packet.opcode = opcode;
    crypto.generateNonce(packet.nonce);
    packet.payload.data = payload.data;
    packet.payload.size = payload.size;
    SyscallManager::SecureMemSet(packet.hmac, 0, ProtocolConstants::HMAC_SIZE);

    bool result = sendPacketToClient(client, packet);

    packet.payload.data = nullptr;
    packet.payload.size = 0;

    return result;
    VMProtectEnd();
}

bool WhipNexusServer::sendEncryptedPacketToClient(ClientSession* client, u16 opcode, const Buffer& payload) {
    VMProtectBeginUltra("WhipNexusServer_sendEncryptedPacketToClient");

    RawPacket packet;
    if (!codec.createEncryptedPacket(opcode, payload, client->sendKey, packet)) {
        return false;
    }

    bool result = sendPacketToClient(client, packet);
    packet.clear();
    return result;
    VMProtectEnd();
}

bool WhipNexusServer::sendToClient(u32 clientId, u16 opcode, const byte* data, u32 length) {
    VMProtectBeginUltra("WhipNexusServer_sendToClient");
    ClientSession* client = findClient(clientId);
    if (!client || !client->active) {
        return false;
    }

    Buffer payload;
    payload.data = (byte*)data;
    payload.size = length;

    bool result = sendEncryptedPacketToClient(client, opcode, payload);
    payload.data = nullptr;
    payload.size = 0;

    return result;
    VMProtectEnd();
}

bool WhipNexusServer::broadcastPacket(u16 opcode, const byte* data, u32 length) {
    VMProtectBeginUltra("WhipNexusServer_broadcastPacket");
    EnterCriticalSection((CRITICAL_SECTION*)clientMutex);

    bool anySuccess = false;
    for (i32 i = 0; i < clientCount; i++) {
        if (clients[i].active) {
            if (sendToClient(clients[i].id, opcode, data, length)) {
                anySuccess = true;
            }
        }
    }

    LeaveCriticalSection((CRITICAL_SECTION*)clientMutex);
    return anySuccess;
    VMProtectEnd();
}

void WhipNexusServer::dispatchPacket(u32 clientId, u16 opcode, const byte* data, u32 length) {
    VMProtectBeginUltra("WhipNexusServer_dispatchPacket");
    for (i32 i = 0; i < handlerCount; i++) {
        if (handlers[i].active && handlers[i].opcode == opcode) {
            handlers[i].handler(clientId, opcode, data, length, handlers[i].context);
            return;
        }
    }
    VMProtectEnd();
}

ClientSession* WhipNexusServer::findClient(u32 clientId) {
    VMProtectBeginUltra("WhipNexusServer_findClient");
    EnterCriticalSection((CRITICAL_SECTION*)clientMutex);

    for (i32 i = 0; i < clientCount; i++) {
        if (clients[i].id == clientId && clients[i].active) {
            LeaveCriticalSection((CRITICAL_SECTION*)clientMutex);
            return &clients[i];
        }
    }

    LeaveCriticalSection((CRITICAL_SECTION*)clientMutex);
    return nullptr;
    VMProtectEnd();
}

void WhipNexusServer::removeClient(u32 clientId) {
    VMProtectBeginUltra("WhipNexusServer_removeClient");
    EnterCriticalSection((CRITICAL_SECTION*)clientMutex);

    SyscallResolver* res = SyscallManager::GetResolver();
    for (i32 i = 0; i < clientCount; i++) {
        if (clients[i].id == clientId) {
            if (clients[i].active) {
                AfdSocket::Close(res, clients[i].socket);
                clients[i].socket = nullptr;
                if (clients[i].privateKey) {
                    crypto.freeKeyHandle(clients[i].privateKey);
                }
                clients[i].active = false;
            }
            break;
        }
    }

    LeaveCriticalSection((CRITICAL_SECTION*)clientMutex);
    VMProtectEnd();
}

u32 WhipNexusServer::addClient(HANDLE socket) {
    VMProtectBeginUltra("WhipNexusServer_addClient");
    EnterCriticalSection((CRITICAL_SECTION*)clientMutex);

    u32 clientId = nextClientId++;

    for (i32 i = 0; i < clientCount; i++) {
        if (!clients[i].active) {
            clients[i].id = clientId;
            clients[i].socket = socket;
            clients[i].authenticated = false;
            clients[i].active = true;
            clients[i].privateKey = nullptr;
            SyscallManager::SecureMemSet(clients[i].sendKey, 0, 32);
            SyscallManager::SecureMemSet(clients[i].recvKey, 0, 32);
            LeaveCriticalSection((CRITICAL_SECTION*)clientMutex);
            return clientId;
        }
    }

    if (clientCount < clientCapacity) {
        clients[clientCount].id = clientId;
        clients[clientCount].socket = socket;
        clients[clientCount].authenticated = false;
        clients[clientCount].active = true;
        clients[clientCount].privateKey = nullptr;
        SyscallManager::SecureMemSet(clients[clientCount].sendKey, 0, 32);
        SyscallManager::SecureMemSet(clients[clientCount].recvKey, 0, 32);
        clientCount++;
        LeaveCriticalSection((CRITICAL_SECTION*)clientMutex);
        return clientId;
    }

    LeaveCriticalSection((CRITICAL_SECTION*)clientMutex);
    VMProtectEnd();
    return 0;
}
