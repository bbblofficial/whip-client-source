#ifndef WHIPNEXUS_TCPSERVERSOCKET_H
#define WHIPNEXUS_TCPSERVERSOCKET_H

#include "Types.h"
#include "whipsyscall/AfdSocket.h"

class TcpServerSocket {
private:
    HANDLE listenSock;
    bool listening;
    u16 boundPort;

public:
    TcpServerSocket();
    ~TcpServerSocket();

    bool bind(const char* host, u16 port);
    bool listen(i32 backlog = 10);
    HANDLE accept();
    void close();

    bool isListening() const { return listening; }
    u16 getPort() const { return boundPort; }
};

#endif // WHIPNEXUS_TCPSERVERSOCKET_H