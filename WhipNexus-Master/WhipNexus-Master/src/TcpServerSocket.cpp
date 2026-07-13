#pragma optimize("", off)
#include "whipnexus/TcpServerSocket.h"
#include "whipnexus/SyscallManager.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

TcpServerSocket::TcpServerSocket()
    : listenSock(nullptr), listening(false), boundPort(0) {
}

TcpServerSocket::~TcpServerSocket() {
    close();
}

bool TcpServerSocket::bind(const char* host, u16 port) {
    if (listening) {
        return false;
    }

    SyscallResolver* res = SyscallManager::GetResolver();
    listenSock = AfdSocket::Create(res);
    if (!listenSock) {
        return false;
    }

    ULONG ip = 0;
    if (host && host[0] != '\0') {
        ip = AfdSocket::ParseIpv4(host);
        if (!ip) {
            AfdSocket::Close(res, listenSock);
            listenSock = nullptr;
            return false;
        }
    }

    if (!AfdSocket::BindTo(res, listenSock, ip, port)) {
        AfdSocket::Close(res, listenSock);
        listenSock = nullptr;
        return false;
    }

    boundPort = port;

    return true;
}

bool TcpServerSocket::listen(i32 backlog) {
    if (!listenSock) {
        return false;
    }

    SyscallResolver* res = SyscallManager::GetResolver();
    if (!AfdSocket::Listen(res, listenSock, static_cast<ULONG>(backlog))) {
        return false;
    }

    if (boundPort == 0) {
        boundPort = AfdSocket::GetLocalPort(res, listenSock);
    }

    listening = true;
    return true;
}

HANDLE TcpServerSocket::accept() {
    if (!listening || !listenSock) {
        return nullptr;
    }

    SyscallResolver* res = SyscallManager::GetResolver();

    ULONG seqNum = 0;
    if (!AfdSocket::WaitForListen(res, listenSock, seqNum)) {
        return nullptr;
    }

    HANDLE clientSock = AfdSocket::Create(res);
    if (!clientSock) {
        return nullptr;
    }

    if (!AfdSocket::Accept(res, listenSock, clientSock, seqNum)) {
        AfdSocket::Close(res, clientSock);
        return nullptr;
    }

    return clientSock;
}

void TcpServerSocket::close() {
    if (listenSock) {
        SyscallResolver* res = SyscallManager::GetResolver();
        AfdSocket::Close(res, listenSock);
        listenSock = nullptr;
    }
    listening = false;
    boundPort = 0;
}
