#ifndef WHIPPIPE_H
#define WHIPPIPE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WhipLoader* WhipLoader;
typedef struct WhipClient* WhipClient;

typedef enum {
    IpcReady = 1,      // DLL → Loader : DLL injectée et prête (ENCRYPTED)
    IpcStatus,         // DLL → Loader : Status périodique (ENCRYPTED)
    IpcError,          // DLL → Loader : Erreur à afficher (ENCRYPTED)
    IpcUnload,         // Loader → DLL : Demande d'unload (ENCRYPTED)
    IpcConfig,         // Loader → DLL : Configuration (ENCRYPTED)
    IpcPing,           // Both : Keepalive / Heartbeat (ENCRYPTED)
    IpcPong,           // Both : Réponse au ping (ENCRYPTED)
    IpcCustom = 128    // Messages custom >= 128 (ENCRYPTED)
} WhipMessageType;

typedef struct {
    WhipMessageType type;
    const unsigned char* data;
    unsigned int len;
} WhipMessage;

typedef void (*WhipMessageHandler)(const WhipMessage* msg, void* user);
typedef void (*WhipConnectHandler)(void* user);
typedef void (*WhipDisconnectHandler)(void* user);
typedef void (*WhipErrorHandler)(const char* error, void* user);

// ─── Loader (côté loader/injecteur) ────────────────────────────────────────

WhipLoader whipLoaderCreate(unsigned short port, const char* host);
void whipLoaderDestroy(WhipLoader loader);

int whipLoaderStart(WhipLoader loader);
int whipLoaderAccept(WhipLoader loader);
int whipLoaderSend(WhipLoader loader, WhipMessageType type, const unsigned char* data, unsigned int len);
int whipLoaderReceive(WhipLoader loader, WhipMessage* outMsg);
void whipLoaderFreeMessage(WhipMessage* msg);

int whipLoaderListenAsync(WhipLoader loader,
                           WhipMessageHandler onMsg,
                           WhipConnectHandler onConn,
                           WhipDisconnectHandler onDisc,
                           WhipErrorHandler onErr,
                           void* user);

void whipLoaderEnableHeartbeat(WhipLoader loader, unsigned int intervalMs);
void whipLoaderStop(WhipLoader loader);
int whipLoaderIsRunning(WhipLoader loader);
int whipLoaderIsConnected(WhipLoader loader);

// ─── Client (côté DLL injectée) ────────────────────────────────────────────

WhipClient whipClientCreate(const char* host, unsigned short port);
void whipClientDestroy(WhipClient client);

int whipClientConnect(WhipClient client, unsigned int timeoutMs);
int whipClientSend(WhipClient client, WhipMessageType type, const unsigned char* data, unsigned int len);
int whipClientReceive(WhipClient client, WhipMessage* outMsg);
void whipClientFreeMessage(WhipMessage* msg);
void whipClientDisconnect(WhipClient client);

int whipClientListenAsync(WhipClient client,
                           WhipMessageHandler onMsg,
                           WhipConnectHandler onConn,
                           WhipDisconnectHandler onDisc,
                           WhipErrorHandler onErr,
                           void* user,
                           unsigned int timeoutMs);

void whipClientEnableHeartbeat(WhipClient client, unsigned int intervalMs);
void whipClientStop(WhipClient client);
int whipClientIsConnected(WhipClient client);

// ─── Helpers ───────────────────────────────────────────────────────────────

const char* whipMessageTypeStr(WhipMessageType type);

#ifdef __cplusplus
}
#endif

#endif