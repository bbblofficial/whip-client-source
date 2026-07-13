#ifndef WHIPNEXUS_TCPSOCKET_H
#define WHIPNEXUS_TCPSOCKET_H

#include "Types.h"
#include "whipsyscall/AfdSocket.h"

// TCP socket backed by direct NT AFD syscalls (no ws2_32 dependency).
// FILE_SYNCHRONOUS_IO_NONALERT ensures all I/O is blocking.
class TcpSocket {
private:
    HANDLE sock;
    bool   connected;

    // Resolver is NOT owned by TcpSocket; caller must keep it alive.
    SyscallResolver* resolver;

    // PERFORMANCE: Internal read buffer to reduce syscalls - MAXIMUM SIZE FOR SPEED
    static const u32 READ_BUFFER_SIZE = 1048576; // 1 MB (~7 syscalls for 6.62MB instead of ~55)
    byte readBuffer[READ_BUFFER_SIZE];
    u32 readBufferPos;   // Current read position in buffer
    u32 readBufferLen;   // Valid bytes in buffer

public:
    TcpSocket();
    explicit TcpSocket(SyscallResolver* res);
    ~TcpSocket();

    // Wire the resolver after default construction (call before connect).
    void init(SyscallResolver* res) { resolver = res; }

    // No-op stubs kept for API compatibility with existing call sites.
    static bool initWinsock();
    static void cleanupWinsock();

    // Connect to host (dotted-decimal IPv4 string) and port.
    bool connect(const char* host, u16 port);

    // Disconnect and close the socket handle.
    void disconnect();

    // Send exactly `length` bytes; retries until all are sent.
    bool send(const byte* data, u32 length);

    // Receive up to `bufferSize` bytes; returns bytes received or -1 on error.
    i32 receive(byte* buffer, u32 bufferSize);

    // Receive exactly `length` bytes; blocks until all arrive.
    bool receiveExact(byte* buffer, u32 length);

    bool isConnected() const { return connected; }

    // Set receive and send timeouts in milliseconds.
    bool setTimeout(u32 timeoutMs);

    // Cancel all pending I/O on this socket (unblocks recv from another thread).
    void cancelIo();
};

#endif // WHIPNEXUS_TCPSOCKET_H