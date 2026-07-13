#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <atomic>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")

class LoaderCommunicator {
public:
    static LoaderCommunicator* getInstance();
    ~LoaderCommunicator();

    bool createPipe();
    bool waitForClient();
    bool waitForClientTimeout(int timeoutMs);
    bool initialize();
    void cleanup();

    void startHeartbeat();
    void stopHeartbeat();

    int receiveMessage(char* outBuffer, int bufferSize, int timeoutMs = 0);
    void sendMessage(const char* message);

    bool isConnected() const;
    bool isClientAlive() const;
    void updateLastHeartbeat();
    void setClientThreadId(DWORD threadId);
    DWORD getClientThreadId() const;
    void terminateClientThread();

    void sendConnectAck();
    void sendHeartbeat();
    void heartbeatLoop();
    bool waitForConnect(int timeoutMs = 0);
    bool waitForClientLoaded(int timeoutMs = 120000);

    int receiveMessageRaw(char *outBuf, int bufSize, int timeoutMs);

    static const char* strStr(const char* haystack, const char* needle);

private:
    LoaderCommunicator();
    LoaderCommunicator(const LoaderCommunicator&) = delete;
    LoaderCommunicator& operator=(const LoaderCommunicator&) = delete;

    bool handleKeyExchange(int timeoutMs);

    void deriveKey(const char* sessionKey, const char* salt, unsigned char* outKey, int keyLen);
    void aesEncrypt(const unsigned char* input, int inputLen, const unsigned char* key, unsigned char* iv, unsigned char* output, int& outputLen);
    void aesDecrypt(const unsigned char* input, int inputLen, const unsigned char* key, unsigned char* iv, unsigned char* output, int& outputLen);
    void hmacSha256(const unsigned char* key, int keyLen, const unsigned char* data, int dataLen, unsigned char* output);
    void sha256(const unsigned char* input, int len, unsigned char* output);

    void encryptMessage(const char* msg, char* encrypted, int& outLen);
    bool decryptMessage(const char* encrypted, char* decrypted);
    bool verifyKey(const char* decrypted);

    static void base64Encode(const unsigned char* input, int len, char* output);
    static int base64Decode(const char* input, unsigned char* output);

    static int strLen(const char* str);
    static void strCopy(char* dest, const char* src, int maxLen);
    static void strCat(char* dest, const char* src, int maxLen);
    static bool strEquals(const char* a, const char* b);
    static void strRemoveChar(char* str, char toRemove);
    static void memCopy(void* dest, const void* src, int len);
    static void memSet(void* dest, int val, int len);

    static LoaderCommunicator* instance;

    SOCKET serverSock;
    SOCKET clientSock;
    HANDLE heartbeatThreadHandle;
    HANDLE stopHeartbeatEvent;
    std::atomic<bool> connected;
    std::atomic<bool> heartbeatRunning;
    std::chrono::steady_clock::time_point lastHeartbeat;

    unsigned char sessionKey[32];
    bool keysEstablished;
    CRITICAL_SECTION cryptoLock;

    DWORD clientThreadId;

    static constexpr int HEARTBEAT_INTERVAL_SEC = 120;
    static constexpr int HEARTBEAT_TIMEOUT_SEC = 180;
    static constexpr int SERVER_PORT = 47832;
    static constexpr const char* VERIFY_KEY = "V3R1FY";
};