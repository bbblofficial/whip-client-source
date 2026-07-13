#include "whippipe_internal.h"

static DWORD WINAPI client_thread_proc(LPVOID param);
static DWORD WINAPI client_heartbeat_proc(LPVOID param);

WhipClient whipClientCreate(const char* host, unsigned short port)
{
    whip_crypto_init();

    HANDLE heap = GetProcessHeap();
    WhipClient c = (WhipClient)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(struct WhipClient));
    if (!c) return NULL;

    c->sock      = INVALID_SOCKET;
    c->port      = port;
    c->running   = 0;
    c->connected = 0;
    c->authenticated = 0;
    c->thread    = NULL;
    c->heartbeat_thread = NULL;
    c->heartbeat_interval_ms = 0;
    c->last_pong_tick = 0;
    c->crypto = NULL;

    whipStrcpySafe(c->host, host ? host : "127.0.0.1", sizeof c->host);
    InitializeCriticalSection(&c->cs);

    return c;
}

void whipClientDestroy(WhipClient c)
{
    if (!c) return;
    whipClientStop(c);
    if (c->crypto) {
        whip_crypto_destroy(c->crypto);
        c->crypto = NULL;
    }
    SecureZeroMemory(c->ecdh_privkey, sizeof(c->ecdh_privkey));
    DeleteCriticalSection(&c->cs);
    HeapFree(GetProcessHeap(), 0, c);
}

int whipClientConnect(WhipClient c, unsigned int timeout_ms)
{
    if (!c) return 0;
    if (InterlockedCompareExchange(&c->connected, 0, 0)) return 1;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 0;

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(c->port);
    inet_pton(AF_INET, c->host, &addr.sin_addr);

    DWORD start = GetTickCount();
    DWORD limit = start + timeout_ms;

    while (1)
    {
        c->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (c->sock == INVALID_SOCKET) {
            WSACleanup();
            return 0;
        }

        if (connect(c->sock, (struct sockaddr*)&addr, sizeof addr) == 0) {
            InterlockedExchange(&c->connected, 1);

            // HANDSHAKE challenge-response ECDH
            if (!whipClientHandshake(c->sock, &c->crypto, c->ecdh_privkey)) {
                closesocket(c->sock);
                c->sock = INVALID_SOCKET;
                InterlockedExchange(&c->connected, 0);
                WSACleanup();
                return 0;
            }

            InterlockedExchange(&c->authenticated, 1);
            InterlockedExchange(&c->running, 1);
            c->last_pong_tick = GetTickCount();
            return 1;
        }

        closesocket(c->sock);
        c->sock = INVALID_SOCKET;

        if (GetTickCount() >= limit) {
            WSACleanup();
            return 0;
        }

        Sleep(50);
    }
}

int whipClientSend(WhipClient c, WhipMessageType type, const unsigned char* data, unsigned int len)
{
    if (!c || !InterlockedCompareExchange(&c->connected, 0, 0))
        return 0;
    if (!InterlockedCompareExchange(&c->authenticated, 0, 0))
        return 0;

    return whipSendMessage(c->sock, c->crypto, type, data, len);
}

int whipClientReceive(WhipClient c, WhipMessage* out_msg)
{
    if (!c || !InterlockedCompareExchange(&c->connected, 0, 0))
        return 0;
    if (!InterlockedCompareExchange(&c->authenticated, 0, 0))
        return 0;

    while (InterlockedCompareExchange(&c->running, 0, 0) &&
           InterlockedCompareExchange(&c->connected, 0, 0))
    {
        if (whipWaitReadable(c->sock, 100))
        {
            if (whipRecvMessage(c->sock, c->crypto, out_msg)) {
                if (out_msg->type == IpcPong)
                    c->last_pong_tick = GetTickCount();
                return 1;
            }
            InterlockedExchange(&c->connected, 0);
            InterlockedExchange(&c->authenticated, 0);
            return 0;
        }
    }

    InterlockedExchange(&c->connected, 0);
    InterlockedExchange(&c->authenticated, 0);
    return 0;
}

void whipClientFreeMessage(WhipMessage* msg)
{
    if (msg && msg->data) {
        HeapFree(GetProcessHeap(), 0, (void*)msg->data);
        msg->data = NULL;
        msg->len = 0;
    }
}

void whipClientDisconnect(WhipClient c)
{
    if (!c) return;

    if (c->sock != INVALID_SOCKET) {
        closesocket(c->sock);
        c->sock = INVALID_SOCKET;
    }

    InterlockedExchange(&c->connected, 0);
}

int whipClientListenAsync(WhipClient c,
                           WhipMessageHandler on_msg,
                           WhipConnectHandler on_conn,
                           WhipDisconnectHandler on_disc,
                           WhipErrorHandler on_err,
                           void* user,
                           unsigned int timeout_ms)
{
    if (!c) return 0;
    if (!whipClientConnect(c, timeout_ms)) return 0;

    c->onMsg  = on_msg;
    c->onConn = on_conn;
    c->onDisc = on_disc;
    c->onErr  = on_err;
    c->user    = user;

    c->thread = CreateThread(NULL, 0, client_thread_proc, c, 0, NULL);
    return c->thread != NULL;
}

static DWORD WINAPI client_thread_proc(LPVOID param)
{
    WhipClient c = (WhipClient)param;

    if (c->onConn) {
        EnterCriticalSection(&c->cs);
        c->onConn(c->user);
        LeaveCriticalSection(&c->cs);
    }

    if (c->heartbeat_interval_ms > 0) {
        c->heartbeat_thread = CreateThread(NULL, 0, client_heartbeat_proc, c, 0, NULL);
    }

    while (InterlockedCompareExchange(&c->running, 0, 0) &&
           InterlockedCompareExchange(&c->connected, 0, 0))
    {
        WhipMessage msg = { 0 };
        if (!whipClientReceive(c, &msg)) break;

        if (msg.type == IpcPing) {
            whipClientSend(c, IpcPong, NULL, 0);
        }
        else if (msg.type == IpcPong) {
            // Already updated last_pong_tick in receive
        }
        else if (c->onMsg) {
            EnterCriticalSection(&c->cs);
            c->onMsg(&msg, c->user);
            LeaveCriticalSection(&c->cs);
        }

        whipClientFreeMessage(&msg);
    }

    InterlockedExchange(&c->connected, 0);

    if (c->heartbeat_thread) {
        WaitForSingleObject(c->heartbeat_thread, INFINITE);
        CloseHandle(c->heartbeat_thread);
        c->heartbeat_thread = NULL;
    }

    if (c->onDisc && InterlockedCompareExchange(&c->running, 0, 0)) {
        EnterCriticalSection(&c->cs);
        c->onDisc(c->user);
        LeaveCriticalSection(&c->cs);
    }

    return 0;
}

static DWORD WINAPI client_heartbeat_proc(LPVOID param)
{
    WhipClient c = (WhipClient)param;

    while (InterlockedCompareExchange(&c->running, 0, 0) &&
           InterlockedCompareExchange(&c->connected, 0, 0))
    {
        Sleep(c->heartbeat_interval_ms);

        if (!InterlockedCompareExchange(&c->connected, 0, 0))
            break;

        DWORD now = GetTickCount();
        DWORD elapsed = now - c->last_pong_tick;

        if (elapsed > c->heartbeat_interval_ms * 3) {
            InterlockedExchange(&c->connected, 0);
            break;
        }

        whipClientSend(c, IpcPing, NULL, 0);
    }

    return 0;
}

void whipClientEnableHeartbeat(WhipClient c, unsigned int interval_ms)
{
    if (c)
        c->heartbeat_interval_ms = interval_ms;
}

void whipClientStop(WhipClient c)
{
    if (!c) return;
    if (!InterlockedCompareExchange(&c->running, 0, 0)) return;

    InterlockedExchange(&c->running, 0);

    if (c->sock != INVALID_SOCKET) {
        closesocket(c->sock);
        c->sock = INVALID_SOCKET;
    }

    if (c->heartbeat_thread) {
        WaitForSingleObject(c->heartbeat_thread, INFINITE);
        CloseHandle(c->heartbeat_thread);
        c->heartbeat_thread = NULL;
    }

    if (c->thread) {
        WaitForSingleObject(c->thread, INFINITE);
        CloseHandle(c->thread);
        c->thread = NULL;
    }

    WSACleanup();
}

int whipClientIsConnected(WhipClient c)
{
    return c ? InterlockedCompareExchange(&c->connected, 0, 0) : 0;
}