#include "Communication/LoaderCommunication.h"
#include "utils/cliUtils.h"

#include <iostream>
#include <ostream>

LoaderCommunicator* LoaderCommunicator::instance = nullptr;

LoaderCommunicator::LoaderCommunicator()
    : serverSock(INVALID_SOCKET), clientSock(INVALID_SOCKET), heartbeatThreadHandle(nullptr),
      stopHeartbeatEvent(nullptr), connected(false), heartbeatRunning(false),
      lastHeartbeat(std::chrono::steady_clock::now()), keysEstablished(false), clientThreadId(0) {
    memSet(sessionKey, 0, 32);
    InitializeCriticalSection(&cryptoLock);
    stopHeartbeatEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
}

LoaderCommunicator::~LoaderCommunicator() {
    cleanup();
    if (stopHeartbeatEvent) CloseHandle(stopHeartbeatEvent);
    DeleteCriticalSection(&cryptoLock);
}

LoaderCommunicator* LoaderCommunicator::getInstance() {
    if (!instance) instance = new LoaderCommunicator();
    return instance;
}

int LoaderCommunicator::strLen(const char* str) {
    int len = 0;
    while (str[len]) len++;
    return len;
}

void LoaderCommunicator::strCopy(char* dest, const char* src, int maxLen) {
    int i = 0;
    while (src[i] && i < maxLen - 1) { dest[i] = src[i]; i++; }
    dest[i] = '\0';
}

void LoaderCommunicator::strCat(char* dest, const char* src, int maxLen) {
    int dLen = strLen(dest), i = 0;
    while (src[i] && (dLen + i) < maxLen - 1) { dest[dLen + i] = src[i]; i++; }
    dest[dLen + i] = '\0';
}

const char* LoaderCommunicator::strStr(const char* hay, const char* needle) {
    if (!*needle) return hay;
    for (int i = 0; hay[i]; i++) {
        int j = 0;
        while (hay[i + j] == needle[j] && needle[j]) j++;
        if (!needle[j]) return &hay[i];
    }
    return nullptr;
}

bool LoaderCommunicator::strEquals(const char* a, const char* b) {
    int i = 0;
    while (a[i] && b[i]) { if (a[i] != b[i]) return false; i++; }
    return a[i] == b[i];
}

void LoaderCommunicator::strRemoveChar(char* str, char c) {
    int i = 0, j = 0;
    while (str[i]) { if (str[i] != c) str[j++] = str[i]; i++; }
    str[j] = '\0';
}

void LoaderCommunicator::memCopy(void* dest, const void* src, int len) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    for (int i = 0; i < len; i++) d[i] = s[i];
}

void LoaderCommunicator::memSet(void* dest, int val, int len) {
    unsigned char* d = (unsigned char*)dest;
    for (int i = 0; i < len; i++) d[i] = (unsigned char)val;
}

void LoaderCommunicator::sha256(const unsigned char* input, int len, unsigned char* output) {
    unsigned int h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    static const unsigned int k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    int ml = len * 8;
    int padLen = ((len + 8) / 64 + 1) * 64;
    unsigned char* msg = new unsigned char[padLen];
    memCopy(msg, input, len);
    msg[len] = 0x80;
    memSet(msg + len + 1, 0, padLen - len - 9);
    for (int i = 0; i < 8; i++) msg[padLen - 1 - i] = (ml >> (i * 8)) & 0xff;

    for (int chunk = 0; chunk < padLen; chunk += 64) {
        unsigned int w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (msg[chunk+i*4]<<24)|(msg[chunk+i*4+1]<<16)|(msg[chunk+i*4+2]<<8)|msg[chunk+i*4+3];
        for (int i = 16; i < 64; i++) {
            unsigned int s0 = ((w[i-15]>>7)|(w[i-15]<<25))^((w[i-15]>>18)|(w[i-15]<<14))^(w[i-15]>>3);
            unsigned int s1 = ((w[i-2]>>17)|(w[i-2]<<15))^((w[i-2]>>19)|(w[i-2]<<13))^(w[i-2]>>10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        unsigned int a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            unsigned int S1 = ((e>>6)|(e<<26))^((e>>11)|(e<<21))^((e>>25)|(e<<7));
            unsigned int ch = (e&f)^((~e)&g);
            unsigned int t1 = hh + S1 + ch + k[i] + w[i];
            unsigned int S0 = ((a>>2)|(a<<30))^((a>>13)|(a<<19))^((a>>22)|(a<<10));
            unsigned int maj = (a&b)^(a&c)^(b&c);
            unsigned int t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    delete[] msg;
    for (int i = 0; i < 8; i++) {
        output[i*4] = (h[i]>>24)&0xff; output[i*4+1] = (h[i]>>16)&0xff;
        output[i*4+2] = (h[i]>>8)&0xff; output[i*4+3] = h[i]&0xff;
    }
}

void LoaderCommunicator::hmacSha256(const unsigned char* key, int keyLen, const unsigned char* data, int dataLen, unsigned char* output) {
    unsigned char kPad[64], iPad[64], oPad[64];
    memSet(kPad, 0, 64);
    if (keyLen > 64) sha256(key, keyLen, kPad);
    else memCopy(kPad, key, keyLen);
    for (int i = 0; i < 64; i++) { iPad[i] = kPad[i] ^ 0x36; oPad[i] = kPad[i] ^ 0x5c; }
    unsigned char* inner = new unsigned char[64 + dataLen];
    memCopy(inner, iPad, 64);
    memCopy(inner + 64, data, dataLen);
    unsigned char innerHash[32];
    sha256(inner, 64 + dataLen, innerHash);
    delete[] inner;
    unsigned char outer[96];
    memCopy(outer, oPad, 64);
    memCopy(outer + 64, innerHash, 32);
    sha256(outer, 96, output);
}

void LoaderCommunicator::deriveKey(const char* sess, const char* salt, unsigned char* out, int outLen) {
    unsigned char combined[256];
    int sLen = strLen(sess), saltLen = strLen(salt);
    memCopy(combined, sess, sLen);
    memCopy(combined + sLen, salt, saltLen);
    unsigned char hash[32];
    sha256(combined, sLen + saltLen, hash);
    for (int i = 0; i < outLen && i < 32; i++) out[i] = hash[i];
}

void LoaderCommunicator::aesEncrypt(const unsigned char* in, int inLen, const unsigned char* key, unsigned char* iv, unsigned char* out, int& outLen) {
    int padLen = ((inLen / 16) + 1) * 16;
    unsigned char* padded = new unsigned char[padLen];
    memCopy(padded, in, inLen);
    unsigned char pad = (unsigned char)(padLen - inLen);
    for (int i = inLen; i < padLen; i++) padded[i] = pad;

    unsigned char prev[16];
    memCopy(prev, iv, 16);

    for (int block = 0; block < padLen; block += 16) {
        unsigned char xored[16];
        for (int i = 0; i < 16; i++) xored[i] = padded[block + i] ^ prev[i];
        for (int i = 0; i < 16; i++) out[block + i] = xored[i] ^ key[i % 32];
        memCopy(prev, out + block, 16);
    }
    outLen = padLen;
    delete[] padded;
}

void LoaderCommunicator::aesDecrypt(const unsigned char* in, int inLen, const unsigned char* key, unsigned char* iv, unsigned char* out, int& outLen) {
    unsigned char prev[16];
    memCopy(prev, iv, 16);

    for (int block = 0; block < inLen; block += 16) {
        unsigned char decrypted[16];
        for (int i = 0; i < 16; i++) decrypted[i] = in[block + i] ^ key[i % 32];
        for (int i = 0; i < 16; i++) out[block + i] = decrypted[i] ^ prev[i];
        memCopy(prev, in + block, 16);
    }

    unsigned char pad = out[inLen - 1];
    outLen = (pad <= 16) ? inLen - pad : inLen;
}

void LoaderCommunicator::base64Encode(const unsigned char* in, int len, char* out) {
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int o = 0, i = 0;
    while (i < len) {
        unsigned char b1 = in[i++];
        unsigned char b2 = (i < len) ? in[i++] : 0;
        unsigned char b3 = (i < len) ? in[i++] : 0;
        out[o++] = b64[b1 >> 2];
        out[o++] = b64[((b1 & 0x03) << 4) | (b2 >> 4)];
        out[o++] = (i > len + 1) ? '=' : b64[((b2 & 0x0F) << 2) | (b3 >> 6)];
        out[o++] = (i > len) ? '=' : b64[b3 & 0x3F];
    }
    out[o] = '\0';
}

int LoaderCommunicator::base64Decode(const char* in, unsigned char* out) {
    static const unsigned char d[128] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3E,0xFF,0xFF,0xFF,0x3F,
        0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0xFF,0xFF,0xFF,0x00,0xFF,0xFF,
        0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
        0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
        0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0xFF,0xFF,0xFF,0xFF,0xFF
    };
    int len = strLen(in), o = 0, i = 0;
    while (i < len && in[i] != '=') {
        unsigned char c1 = d[(unsigned char)in[i++]]; if (i >= len) break;
        unsigned char c2 = d[(unsigned char)in[i++]]; if (i >= len) break;
        unsigned char c3 = d[(unsigned char)in[i++]]; if (i >= len) break;
        unsigned char c4 = d[(unsigned char)in[i++]];
        out[o++] = (c1 << 2) | (c2 >> 4);
        if (in[i-2] != '=') out[o++] = (c2 << 4) | (c3 >> 2);
        if (in[i-1] != '=') out[o++] = (c3 << 6) | c4;
    }
    return o;
}

void LoaderCommunicator::encryptMessage(const char* msg, char* encrypted, int& outLen) {
    EnterCriticalSection(&cryptoLock);
    unsigned char iv[16];
    LARGE_INTEGER pc; QueryPerformanceCounter(&pc);
    for (int i = 0; i < 16; i++) iv[i] = ((unsigned char*)&pc.QuadPart)[i % 8] ^ sessionKey[i];

    int msgLen = strLen(msg);
    unsigned char* enc = new unsigned char[msgLen + 32];
    int encLen;
    aesEncrypt((const unsigned char*)msg, msgLen, sessionKey, iv, enc, encLen);

    unsigned char* final = new unsigned char[16 + encLen];
    memCopy(final, iv, 16);
    memCopy(final + 16, enc, encLen);

    base64Encode(final, 16 + encLen, encrypted);
    outLen = strLen(encrypted);

    delete[] enc; delete[] final;
    LeaveCriticalSection(&cryptoLock);
}

bool LoaderCommunicator::decryptMessage(const char* encrypted, char* decrypted) {
    EnterCriticalSection(&cryptoLock);
    unsigned char raw[4096];
    int rawLen = base64Decode(encrypted, raw);

    if (rawLen < 17) {
        LeaveCriticalSection(&cryptoLock);
        return false;
    }

    unsigned char iv[16];
    memCopy(iv, raw, 16);

    int decLen;
    aesDecrypt(raw + 16, rawLen - 16, sessionKey, iv, (unsigned char*)decrypted, decLen);
    decrypted[decLen] = '\0';

    LeaveCriticalSection(&cryptoLock);
    return true;
}

bool LoaderCommunicator::verifyKey(const char* decrypted) {
    return strStr(decrypted, VERIFY_KEY) != nullptr;
}

bool LoaderCommunicator::handleKeyExchange(int timeoutMs) {
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(clientSock, &readSet);
    timeval tv = { timeoutMs / 1000, (timeoutMs % 1000) * 1000 };

    if (select(0, &readSet, nullptr, nullptr, &tv) <= 0) return false;

    char buf[256];
    int r = recv(clientSock, buf, 255, 0);
    if (r <= 0) return false;
    buf[r] = '\0';

    strRemoveChar(buf, '\n');
    strRemoveChar(buf, '\r');

    if (!strStr(buf, "KEYEX:")) return false;

    unsigned char recvKey[128];
    memSet(recvKey, 0, 128);
    int keyLen = base64Decode(buf + 6, recvKey);
    if (keyLen < 32) return false;

    memCopy(sessionKey, recvKey, 32);

    keysEstablished = true;

    const char* ack = "KEYACK";
    send(clientSock, ack, strLen(ack), 0);
    return true;
}

bool LoaderCommunicator::createPipe() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;

    serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSock == INVALID_SOCKET) { WSACleanup(); return false; }

    int opt = 1;
    setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(SERVER_PORT);

    if (bind(serverSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(serverSock); serverSock = INVALID_SOCKET;
        WSACleanup(); return false;
    }

    if (listen(serverSock, 1) == SOCKET_ERROR) {
        closesocket(serverSock); serverSock = INVALID_SOCKET;
        WSACleanup(); return false;
    }

    return true;
}

bool LoaderCommunicator::waitForClient() {
    return waitForClientTimeout(60000);
}

bool LoaderCommunicator::waitForClientTimeout(int timeoutMs) {
    if (serverSock == INVALID_SOCKET) {
        return false;
    }

    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(serverSock, &readSet);
    timeval tv = { timeoutMs / 1000, (timeoutMs % 1000) * 1000 };

    int selectResult = select(0, &readSet, nullptr, nullptr, &tv);
    if (selectResult <= 0) {
        return false;
    }

    clientSock = accept(serverSock, nullptr, nullptr);

    if (clientSock == INVALID_SOCKET) {

        return false;
    }

    if (!handleKeyExchange(10000)) {
        closesocket(clientSock);
        clientSock = INVALID_SOCKET;

        return false;
    }

    connected = true;

    if (!waitForConnect(60000)) {
        connected = false;
        closesocket(clientSock);
        clientSock = INVALID_SOCKET;

        return false;
    }

    lastHeartbeat = std::chrono::steady_clock::now();
    return true;
}

bool LoaderCommunicator::initialize() {
    if (!createPipe()) return false;
    if (!waitForClient()) return false;
    return true;
}

void LoaderCommunicator::cleanup() {
    stopHeartbeat();
    connected = false;
    if (clientSock != INVALID_SOCKET) {
        shutdown(clientSock, SD_BOTH);
        closesocket(clientSock);
        clientSock = INVALID_SOCKET;
    }
    if (serverSock != INVALID_SOCKET) {
        closesocket(serverSock);
        serverSock = INVALID_SOCKET;
    }
    WSACleanup();
    memSet(sessionKey, 0, 32);
    keysEstablished = false;
}

static DWORD WINAPI LoaderHeartbeatProc(LPVOID p) {
    ((LoaderCommunicator*)p)->heartbeatLoop();
    return 0;
}

void LoaderCommunicator::startHeartbeat() {
    if (heartbeatRunning.load()) return;
    if (!stopHeartbeatEvent) return;
    ResetEvent(stopHeartbeatEvent);
    heartbeatRunning.store(true);
    heartbeatThreadHandle = CreateThread(nullptr, 0, LoaderHeartbeatProc, this, 0, nullptr);
    if (!heartbeatThreadHandle) heartbeatRunning.store(false);
}

void LoaderCommunicator::stopHeartbeat() {
    if (!heartbeatRunning.load()) return;
    heartbeatRunning.store(false);
    if (stopHeartbeatEvent) SetEvent(stopHeartbeatEvent);
    if (heartbeatThreadHandle) {
        WaitForSingleObject(heartbeatThreadHandle, 10000);
        CloseHandle(heartbeatThreadHandle);
        heartbeatThreadHandle = nullptr;
    }
}

void LoaderCommunicator::heartbeatLoop() {
    while (heartbeatRunning.load() && connected.load()) {
        if (!stopHeartbeatEvent) break;
        DWORD r = WaitForSingleObject(stopHeartbeatEvent, HEARTBEAT_INTERVAL_SEC * 1000);
        if (r == WAIT_OBJECT_0) break;
        if (!heartbeatRunning.load() || !connected.load()) break;
        if (r == WAIT_TIMEOUT && clientSock != INVALID_SOCKET) sendHeartbeat();
    }
}

void LoaderCommunicator::sendConnectAck() { sendMessage("ConnectAck"); }
void LoaderCommunicator::sendHeartbeat() { sendMessage("HeartBeat"); }

bool LoaderCommunicator::waitForConnect(int timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    char buf[4096];

    while (true) {
        if (timeoutMs > 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
            if (elapsed >= timeoutMs) {
                return false;
            }
        }

        int len = receiveMessageRaw(buf, sizeof(buf), 100);
        if (len > 0) {
            if (strStr(buf, "Connect:")) {
                if (verifyKey(buf)) {
                    sendConnectAck();
                    startHeartbeat();
                    return true;
                }
                return false;
            }
        }
        Sleep(50);
    }
}

int LoaderCommunicator::receiveMessageRaw(char* outBuf, int bufSize, int timeoutMs) {
    if (clientSock == INVALID_SOCKET) return 0;

    if (timeoutMs > 0) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(clientSock, &readSet);
        timeval tv = { timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
        if (select(0, &readSet, nullptr, nullptr, &tv) <= 0) return 0;
    }

    char buf[8192];
    int r = recv(clientSock, buf, sizeof(buf) - 1, 0);
    if (r <= 0) return 0;
    buf[r] = '\0';
    strRemoveChar(buf, '\n');
    strRemoveChar(buf, '\r');

    char dec[4096];
    if (decryptMessage(buf, dec)) {
        int len = strLen(dec);
        if (len < bufSize) { strCopy(outBuf, dec, bufSize); return len; }
        strCopy(outBuf, dec, bufSize);
        return bufSize - 1;
    }
    return 0;
}

int LoaderCommunicator::receiveMessage(char* outBuf, int bufSize, int timeoutMs) {
    if (!connected || clientSock == INVALID_SOCKET) return 0;

    int len = receiveMessageRaw(outBuf, bufSize, timeoutMs);
    if (len > 0 && strStr(outBuf, "HeartBeat")) {
        updateLastHeartbeat();
    }
    return len;
}

void LoaderCommunicator::sendMessage(const char* msg) {
    if (!connected || clientSock == INVALID_SOCKET) return;
    char enc[8192];
    int encLen;
    encryptMessage(msg, enc, encLen);
    strCat(enc, "\n", sizeof(enc));
    send(clientSock, enc, strLen(enc), 0);
}

bool LoaderCommunicator::isConnected() const { return connected; }

bool LoaderCommunicator::isClientAlive() const {
    if (!connected) return false;
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastHeartbeat).count();
    return elapsed < HEARTBEAT_TIMEOUT_SEC;
}

void LoaderCommunicator::updateLastHeartbeat() { lastHeartbeat = std::chrono::steady_clock::now(); }

void LoaderCommunicator::setClientThreadId(DWORD threadId) {
    clientThreadId = threadId;
}

DWORD LoaderCommunicator::getClientThreadId() const {
    return clientThreadId;
}

void LoaderCommunicator::terminateClientThread() {
    if (clientThreadId == 0) {
        return;
    }

    HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, clientThreadId);
    if (hThread != nullptr) {
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
    } else {
    }
    clientThreadId = 0;
}

bool LoaderCommunicator::waitForClientLoaded(int timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    char buf[4096];

    while (true) {
        if (timeoutMs > 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
            if (elapsed >= timeoutMs) {
                return false;
            }
        }

        memSet(buf, 0, sizeof(buf));
        int len = receiveMessageRaw(buf, sizeof(buf) - 1, 100);

        if (len > 0) {
            buf[len] = '\0';

            // Nettoyer les caractères indésirables
            for (int i = 0; i < len; i++) {
                if (buf[i] < 32 && buf[i] != '\0') {
                    buf[i] = '\0';
                    break;
                }
            }

            // Message "ClientLoaded" = client prêt
            if (strStr(buf, "ClientLoaded") != nullptr) {
                return true;
            }
            // Message "LoadStep:current:total:message"
            else if (strStr(buf, "LoadStep:") != nullptr) {
                const char* ptr = buf + 9; // Après "LoadStep:"

                // Parser current
                int currentStep = 0;
                while (*ptr >= '0' && *ptr <= '9') {
                    currentStep = currentStep * 10 + (*ptr - '0');
                    ptr++;
                }
                if (*ptr == ':') ptr++;

                // Parser total
                int totalSteps = 0;
                while (*ptr >= '0' && *ptr <= '9') {
                    totalSteps = totalSteps * 10 + (*ptr - '0');
                    ptr++;
                }
                if (*ptr == ':') ptr++;

                // Copier le message dans un buffer propre
                char cleanMsg[256];
                int msgIdx = 0;
                while (*ptr != '\0' && msgIdx < 255) {
                    // Ne garder que les caractères imprimables
                    if (*ptr >= 32 && *ptr < 127) {
                        cleanMsg[msgIdx++] = *ptr;
                    }
                    ptr++;
                }
                cleanMsg[msgIdx] = '\0';

                if (msgIdx > 0 && totalSteps > 0) {
                    Utils::showStep(cleanMsg, currentStep, totalSteps);
                }
            }
            // HeartBeat
            else if (strStr(buf, "HeartBeat") != nullptr) {
                updateLastHeartbeat();
            }
        }
        Sleep(50);
    }
}