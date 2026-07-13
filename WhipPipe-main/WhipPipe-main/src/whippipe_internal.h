#ifndef WHIPPIPE_INTERNAL_H
#define WHIPPIPE_INTERNAL_H

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "../include/whippipe.h"
#include "crypto.h"

struct WhipLoader
{
    SOCKET listen_sock;
    SOCKET client_sock;
    char host[64];
    unsigned short port;
    volatile long running;
    volatile long connected;
    volatile long authenticated;
    HANDLE thread;
    HANDLE heartbeat_thread;
    unsigned int heartbeat_interval_ms;
    DWORD last_pong_tick;
    CRITICAL_SECTION cs;

    whip_crypto_ctx* crypto;
    unsigned char ecdh_privkey[WHIP_ECDH_PRIVKEY_SIZE];
    unsigned char challenge[WHIP_CHALLENGE_SIZE];

    WhipMessageHandler onMsg;
    WhipConnectHandler onConn;
    WhipDisconnectHandler onDisc;
    WhipErrorHandler onErr;
    void* user;
};

struct WhipClient
{
    SOCKET sock;
    char host[64];
    unsigned short port;
    volatile long running;
    volatile long connected;
    volatile long authenticated;
    HANDLE thread;
    HANDLE heartbeat_thread;
    unsigned int heartbeat_interval_ms;
    DWORD last_pong_tick;
    CRITICAL_SECTION cs;

    whip_crypto_ctx* crypto;
    unsigned char ecdh_privkey[WHIP_ECDH_PRIVKEY_SIZE];

    WhipMessageHandler onMsg;
    WhipConnectHandler onConn;
    WhipDisconnectHandler onDisc;
    WhipErrorHandler onErr;
    void* user;
};

#pragma pack(push, 1)
typedef struct {
    unsigned int total_len;
    unsigned char msg_type;
} whip_wire_header;
#pragma pack(pop)

int whipRecvExact(SOCKET sock, void* buf, unsigned int count);
int whipSendExact(SOCKET sock, const void* buf, unsigned int count);
int whipWaitReadable(SOCKET sock, int timeoutMs);
void whipStrcpySafe(char* dst, const char* src, unsigned int dstSize);

int whipSendMessage(SOCKET sock, whip_crypto_ctx* crypto, WhipMessageType type, const unsigned char* data, unsigned int len);
int whipRecvMessage(SOCKET sock, whip_crypto_ctx* crypto, WhipMessage* outMsg);

int whipLoaderHandshake(SOCKET sock, whip_crypto_ctx** cryptoOut, unsigned char* privkey, unsigned char* challenge);
int whipClientHandshake(SOCKET sock, whip_crypto_ctx** cryptoOut, unsigned char* privkey);

#endif