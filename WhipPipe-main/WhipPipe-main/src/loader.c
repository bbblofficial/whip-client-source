#include "whippipe_internal.h"

static DWORD WINAPI loader_thread_proc(LPVOID param);
static DWORD WINAPI loader_heartbeat_proc(LPVOID param);

WhipLoader whipLoaderCreate(unsigned short port, const char* host)
{
    whip_crypto_init();

    HANDLE heap = GetProcessHeap();
    WhipLoader l = (WhipLoader)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(struct WhipLoader));
    if (!l) return NULL;

    l->listen_sock = INVALID_SOCKET;
    l->client_sock = INVALID_SOCKET;
    l->port        = port;
    l->running     = 0;
    l->connected   = 0;
    l->authenticated = 0;
    l->thread      = NULL;
    l->heartbeat_thread = NULL;
    l->heartbeat_interval_ms = 0;
    l->last_pong_tick = 0;
    l->crypto = NULL;

    whipStrcpySafe(l->host, host ? host : "127.0.0.1", sizeof l->host);
    InitializeCriticalSection(&l->cs);

    return l;
}

void whipLoaderDestroy(WhipLoader l)
{
    if (!l) return;
    whipLoaderStop(l);
    if (l->crypto) {
        whip_crypto_destroy(l->crypto);
        l->crypto = NULL;
    }
    SecureZeroMemory(l->ecdh_privkey, sizeof(l->ecdh_privkey));
    SecureZeroMemory(l->challenge, sizeof(l->challenge));
    DeleteCriticalSection(&l->cs);
    HeapFree(GetProcessHeap(), 0, l);
}

int whipLoaderStart(WhipLoader l)
{
    if (!l) return 0;
    if (InterlockedCompareExchange(&l->running, 0, 0)) return 1;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 0;

    l->listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (l->listen_sock == INVALID_SOCKET) {
        WSACleanup();
        return 0;
    }

    int opt = 1;
    setsockopt(l->listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof opt);

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(l->port);
    inet_pton(AF_INET, l->host, &addr.sin_addr);

    if (bind(l->listen_sock, (struct sockaddr*)&addr, sizeof addr) == SOCKET_ERROR) {
        closesocket(l->listen_sock);
        l->listen_sock = INVALID_SOCKET;
        WSACleanup();
        return 0;
    }

    if (listen(l->listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(l->listen_sock);
        l->listen_sock = INVALID_SOCKET;
        WSACleanup();
        return 0;
    }

    InterlockedExchange(&l->running, 1);
    return 1;
}

int whipLoaderAccept(WhipLoader l)
{
    if (!l || !InterlockedCompareExchange(&l->running, 0, 0))
        return 0;

    if (InterlockedCompareExchange(&l->connected, 0, 0)) {
        closesocket(l->client_sock);
        l->client_sock = INVALID_SOCKET;
        InterlockedExchange(&l->connected, 0);
        InterlockedExchange(&l->authenticated, 0);
        if (l->crypto) {
            whip_crypto_destroy(l->crypto);
            l->crypto = NULL;
        }
    }

    while (InterlockedCompareExchange(&l->running, 0, 0)) {
        if (whipWaitReadable(l->listen_sock, 100)) {
            l->client_sock = accept(l->listen_sock, NULL, NULL);
            if (l->client_sock != INVALID_SOCKET) {
                InterlockedExchange(&l->connected, 1);

                // HANDSHAKE challenge-response ECDH
                if (!whipLoaderHandshake(l->client_sock, &l->crypto, l->ecdh_privkey, l->challenge)) {
                    closesocket(l->client_sock);
                    l->client_sock = INVALID_SOCKET;
                    InterlockedExchange(&l->connected, 0);
                    return 0;
                }

                InterlockedExchange(&l->authenticated, 1);
                l->last_pong_tick = GetTickCount();
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

int whipLoaderSend(WhipLoader l, WhipMessageType type, const unsigned char* data, unsigned int len)
{
    if (!l || !InterlockedCompareExchange(&l->connected, 0, 0))
        return 0;
    if (!InterlockedCompareExchange(&l->authenticated, 0, 0))
        return 0;

    return whipSendMessage(l->client_sock, l->crypto, type, data, len);
}

int whipLoaderReceive(WhipLoader l, WhipMessage* out_msg)
{
    if (!l || !InterlockedCompareExchange(&l->connected, 0, 0))
        return 0;
    if (!InterlockedCompareExchange(&l->authenticated, 0, 0))
        return 0;

    while (InterlockedCompareExchange(&l->running, 0, 0) &&
           InterlockedCompareExchange(&l->connected, 0, 0))
    {
        if (whipWaitReadable(l->client_sock, 100))
        {
            if (whipRecvMessage(l->client_sock, l->crypto, out_msg)) {
                if (out_msg->type == IpcPong)
                    l->last_pong_tick = GetTickCount();
                return 1;
            }
            InterlockedExchange(&l->connected, 0);
            InterlockedExchange(&l->authenticated, 0);
            return 0;
        }
    }

    InterlockedExchange(&l->connected, 0);
    InterlockedExchange(&l->authenticated, 0);
    return 0;
}

void whipLoaderFreeMessage(WhipMessage* msg)
{
    if (msg && msg->data) {
        HeapFree(GetProcessHeap(), 0, (void*)msg->data);
        msg->data = NULL;
        msg->len = 0;
    }
}

int whipLoaderListenAsync(WhipLoader l,
                           WhipMessageHandler on_msg,
                           WhipConnectHandler on_conn,
                           WhipDisconnectHandler on_disc,
                           WhipErrorHandler on_err,
                           void* user)
{
    if (!l) return 0;
    if (!whipLoaderStart(l)) return 0;

    l->onMsg  = on_msg;
    l->onConn = on_conn;
    l->onDisc = on_disc;
    l->onErr  = on_err;
    l->user    = user;

    l->thread = CreateThread(NULL, 0, loader_thread_proc, l, 0, NULL);
    return l->thread != NULL;
}

static DWORD WINAPI loader_thread_proc(LPVOID param)
{
    WhipLoader l = (WhipLoader)param;

    while (InterlockedCompareExchange(&l->running, 0, 0))
    {
        if (!whipLoaderAccept(l)) break;

        if (l->onConn) {
            EnterCriticalSection(&l->cs);
            l->onConn(l->user);
            LeaveCriticalSection(&l->cs);
        }

        if (l->heartbeat_interval_ms > 0) {
            l->heartbeat_thread = CreateThread(NULL, 0, loader_heartbeat_proc, l, 0, NULL);
        }

        while (InterlockedCompareExchange(&l->running, 0, 0) &&
               InterlockedCompareExchange(&l->connected, 0, 0))
        {
            WhipMessage msg = { 0 };
            if (!whipLoaderReceive(l, &msg)) break;

            if (msg.type == IpcPing) {
                whipLoaderSend(l, IpcPong, NULL, 0);
            }
            else if (msg.type == IpcPong) {
                // Already updated last_pong_tick in receive
            }
            else if (l->onMsg) {
                EnterCriticalSection(&l->cs);
                l->onMsg(&msg, l->user);
                LeaveCriticalSection(&l->cs);
            }

            whipLoaderFreeMessage(&msg);
        }

        InterlockedExchange(&l->connected, 0);

        if (l->heartbeat_thread) {
            WaitForSingleObject(l->heartbeat_thread, INFINITE);
            CloseHandle(l->heartbeat_thread);
            l->heartbeat_thread = NULL;
        }

        if (l->onDisc && InterlockedCompareExchange(&l->running, 0, 0)) {
            EnterCriticalSection(&l->cs);
            l->onDisc(l->user);
            LeaveCriticalSection(&l->cs);
        }
    }

    return 0;
}

static DWORD WINAPI loader_heartbeat_proc(LPVOID param)
{
    WhipLoader l = (WhipLoader)param;

    while (InterlockedCompareExchange(&l->running, 0, 0) &&
           InterlockedCompareExchange(&l->connected, 0, 0))
    {
        Sleep(l->heartbeat_interval_ms);

        if (!InterlockedCompareExchange(&l->connected, 0, 0))
            break;

        DWORD now = GetTickCount();
        DWORD elapsed = now - l->last_pong_tick;

        if (elapsed > l->heartbeat_interval_ms * 3) {
            InterlockedExchange(&l->connected, 0);
            break;
        }

        whipLoaderSend(l, IpcPing, NULL, 0);
    }

    return 0;
}

void whipLoaderEnableHeartbeat(WhipLoader l, unsigned int interval_ms)
{
    if (l)
        l->heartbeat_interval_ms = interval_ms;
}

void whipLoaderStop(WhipLoader l)
{
    if (!l) return;
    if (!InterlockedCompareExchange(&l->running, 0, 0)) return;

    InterlockedExchange(&l->running, 0);

    if (l->client_sock != INVALID_SOCKET) {
        closesocket(l->client_sock);
        l->client_sock = INVALID_SOCKET;
    }
    if (l->listen_sock != INVALID_SOCKET) {
        closesocket(l->listen_sock);
        l->listen_sock = INVALID_SOCKET;
    }

    if (l->heartbeat_thread) {
        WaitForSingleObject(l->heartbeat_thread, INFINITE);
        CloseHandle(l->heartbeat_thread);
        l->heartbeat_thread = NULL;
    }

    if (l->thread) {
        WaitForSingleObject(l->thread, INFINITE);
        CloseHandle(l->thread);
        l->thread = NULL;
    }

    WSACleanup();
}

int whipLoaderIsRunning(WhipLoader l)
{
    return l ? InterlockedCompareExchange(&l->running, 0, 0) : 0;
}

int whipLoaderIsConnected(WhipLoader l)
{
    return l ? InterlockedCompareExchange(&l->connected, 0, 0) : 0;
}