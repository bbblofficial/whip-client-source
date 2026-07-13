#pragma optimize("", off)
#include "whipnexus/TcpSocket.h"
#include "whipnexus/SyscallManager.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

bool TcpSocket::initWinsock() {
    return true;
}

void TcpSocket::cleanupWinsock() {
}

TcpSocket::TcpSocket()
    : sock(nullptr), connected(false), resolver(nullptr), readBufferPos(0), readBufferLen(0) {
}

TcpSocket::TcpSocket(SyscallResolver* res)
    : sock(nullptr), connected(false), resolver(res), readBufferPos(0), readBufferLen(0) {
}

TcpSocket::~TcpSocket() {
    disconnect();
}

bool TcpSocket::connect(const char* host, u16 port) {
    if (!resolver) {
        return false;
    }

    if (connected) disconnect();

    ULONG ip = AfdSocket::ParseIpv4(host);
    if (!ip) {
        return false;
    }

    sock = AfdSocket::Create(resolver);
    if (!sock) {
        return false;
    }

    if (!AfdSocket::Connect(resolver, sock, ip, port)) {
        AfdSocket::Close(resolver, sock);
        sock = nullptr;
        return false;
    }

    connected = true;
    readBufferPos = 0;
    readBufferLen = 0;
    return true;
}

void TcpSocket::disconnect() {
    if (sock) {
        AfdSocket::Disconnect(resolver, sock, false);
        AfdSocket::Close(resolver, sock);
        sock = nullptr;
    }
    connected = false;
    readBufferPos = 0;
    readBufferLen = 0;
}

bool TcpSocket::send(const byte* data, u32 length) {
    if (!connected || !sock) { return false; }

    u32 totalSent = 0;
    while (totalSent < length) {
        ULONG sent = 0;
        if (!AfdSocket::Send(resolver, sock,
                             data + totalSent, length - totalSent, sent)) {
            disconnect();
            return false;
        }
        totalSent += sent;
    }
    return true;
}

i32 TcpSocket::receive(byte* buffer, u32 bufferSize) {
    if (!connected || !sock) { return -1; }

    ULONG received = 0;
    if (!AfdSocket::Recv(resolver, sock, buffer, bufferSize, received)) {
        disconnect();
        return -1;
    }
    i32 result = static_cast<i32>(received);
    return result;
}

bool TcpSocket::receiveExact(byte* buffer, u32 length) {
    if (!connected || !sock) { return false; }

    u32 totalRecv = 0;

    while (totalRecv < length) {
        u32 bufferAvail = readBufferLen - readBufferPos;

        if (bufferAvail > 0) {
            u32 toCopy = (length - totalRecv < bufferAvail) ? (length - totalRecv) : bufferAvail;
            SyscallManager::SecureMemCpy(buffer + totalRecv, readBuffer + readBufferPos, toCopy);
            readBufferPos += toCopy;
            totalRecv += toCopy;
        } else {
            readBufferPos = 0;
            readBufferLen = 0;

            ULONG received = 0;
            if (!AfdSocket::Recv(resolver, sock, readBuffer, READ_BUFFER_SIZE, received)) {
                disconnect();
                return false;
            }
            if (received == 0) {
                disconnect();
                return false;
            }
            readBufferLen = received;
        }
    }

    return true;
}

bool TcpSocket::setTimeout(u32 timeoutMs) {
    if (!sock) { return false; }
    return AfdSocket::SetTimeout(resolver, sock, timeoutMs, timeoutMs);
}

void TcpSocket::cancelIo() {
    if (!sock || !resolver) { return; }

    WORD ssn;
    PVOID addr;
    if (resolver->ResolveByName("NtCancelIoFile", ssn, addr)) {
        IO_STATUS_BLOCK ioStatus = { 0 };
        SyscallInvoker::Invoke(ssn, sock, &ioStatus);
    }
}
