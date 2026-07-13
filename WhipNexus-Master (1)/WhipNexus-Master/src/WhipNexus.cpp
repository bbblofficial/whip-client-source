#pragma optimize("", off)
#include "whipnexus/WhipNexus.h"

#include "whipnexus/SyscallManager.h"
#include "antidebug/vm/vm_cpp.hpp"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

namespace {
    // WhipVM helpers : encode/decode du flag connectedVmEncoded.
    // 0 décodé = connecté, sinon non. NOPer un site (encode OU decode) seul
    // désynchronise — et le runtime key dérivé de l'ASLR doit être reproduit.
    //
    // IMPORTANT: vm_runtime_key_stable() lit TEB.Self qui est per-thread. On
    // cache la valeur au premier appel (typiquement main thread / ctor) pour
    // que les autres threads (event loop, etc.) décodent avec la même clé.
    // C++11 magic static = init thread-safe.
    inline u32 cachedRtKey() {
        static const u32 key = vm_runtime_key_stable();
        return key;
    }

    inline u64 encodeConnectedFlag(u32 v) {
        auto cascade = ad::vm::ScoreCascade::from_key(cachedRtKey());
        return cascade.encode(v);
    }

    inline bool decodeConnectedIsTrue(u64 encoded) {
        auto cascade = ad::vm::ScoreCascade::from_key(cachedRtKey());
        return cascade.decode(encoded) == 0u;
    }

    // SplitMix64 — same constants used by the WhipAntiDebugger framework.
    inline u64 mix64(u64 x) {
        x += 0x9E3779B97F4A7C15ULL;
        x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
        x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
        return x ^ (x >> 31);
    }

    // Fingerprint of sessionKey (32 bytes = 4 × u64). Returned value bound
    // to the actual ECDH-derived key — connect() that skips handshake leaves
    // sessionKey zero and produces a different (constant) fingerprint.
    inline u64 connectionProofOf(const byte sessionKey[32]) {
        const u64* sk = reinterpret_cast<const u64*>(sessionKey);
        u64 h = 0xC0FFEE13DEADB33FULL;
        h = mix64(h ^ sk[0]);
        h = mix64(h ^ sk[1]);
        h = mix64(h ^ sk[2]);
        h = mix64(h ^ sk[3]);
        return h;
    }

    // Fingerprint of (enabled, pinnedCertificateHash). Set by
    // setCertificatePinning() and recomputed in performHandshake() to
    // detect direct memory tampering with the `certificatePinningEnabled`
    // flag. If a reverser flips it, the proof no longer matches → handshake
    // forces the cert check anyway as if pinning were on.
    inline u64 pinningProofOf(bool enabled, const byte hash[32]) {
        const u64* h64 = reinterpret_cast<const u64*>(hash);
        u64 h = enabled ? 0x57484950F1F1F1F1ULL : 0xDEADBEEFDEADBEEFULL;
        h = mix64(h ^ h64[0]);
        h = mix64(h ^ h64[1]);
        h = mix64(h ^ h64[2]);
        h = mix64(h ^ h64[3]);
        return h;
    }
}

WhipNexus::WhipNexus()
    : codec(&crypto), clientPrivateKey(nullptr),
      clientPublicKeyLength(0),
      handlerCount(0), eventThread(nullptr), running(false), connected(false), connectedProof(0),
      connectedVmEncoded(encodeConnectedFlag(0xFFu)),
      sendMutex(nullptr), ioMutex(nullptr), lastErrorCode(0),
      nonceHistoryIndex(0), nonceHistoryCount(0),
      certificatePinningEnabled(false), pinningProof(0) {
    VMProtectBeginUltra("WhipNexus_ctor");
    SyscallManager::SecureZero(sendKey, sizeof(sendKey));
    SyscallManager::SecureZero(recvKey, sizeof(recvKey));
    SyscallManager::SecureZero(sessionKey, sizeof(sessionKey));
    SyscallManager::SecureZero(nonceHistory, sizeof(nonceHistory));
    SyscallManager::SecureZero(clientPublicKey, sizeof(clientPublicKey));
    SyscallManager::SecureZero(handlers, sizeof(handlers));
    SyscallManager::SecureZero(pinnedCertificateHash, sizeof(pinnedCertificateHash));
    VMProtectEnd();
}

WhipNexus::~WhipNexus() {
    VMProtectBeginUltra("WhipNexus_dtor");
    disconnect();
    if (clientPrivateKey) {
        crypto.freeKeyHandle(clientPrivateKey);
        clientPrivateKey = nullptr;
    }
    if (sendMutex) {
        SyscallManager::DeleteCriticalSection(sendMutex);
        sendMutex = nullptr;
    }
    if (ioMutex) {
        SyscallManager::DeleteCriticalSection(ioMutex);
        ioMutex = nullptr;
    }
    SyscallManager::Cleanup();
    VMProtectEnd();
}

bool WhipNexus::isNonceReplay(const byte* nonce) {
    VMProtectBeginUltra("WhipNexus_isNonceReplay");
    i32 count = (nonceHistoryCount < NONCE_HISTORY_SIZE) ? nonceHistoryCount : NONCE_HISTORY_SIZE;
    for (i32 i = 0; i < count; i++) {
        i32 diff = 0;
        for (i32 j = 0; j < 12; j++) {
            diff |= nonceHistory[i][j] ^ nonce[j];
        }
        if (diff == 0) { return true; }
    }

    SyscallManager::SecureMemCpy(nonceHistory[nonceHistoryIndex], nonce, 12);
    nonceHistoryIndex = (nonceHistoryIndex + 1) % NONCE_HISTORY_SIZE;
    if (nonceHistoryCount < NONCE_HISTORY_SIZE) nonceHistoryCount++;

    return false;
    VMProtectEnd();
}

bool WhipNexus::init() {
    VMProtectBeginUltra("WhipNexus_init");
    if (!SyscallManager::Init()) {
        return false;
    }

    socket.init(SyscallManager::GetResolver(), &crypto);

    if (!crypto.init()) {
        return false;
    }

    sendMutex = SyscallManager::CreateCriticalSection();
    if (!sendMutex) {
        return false;
    }

    ioMutex = SyscallManager::CreateCriticalSection();
    if (!ioMutex) {
        return false;
    }

    return true;
    VMProtectEnd();
}

void WhipNexus::setPlainMode(bool enabled) {
    VMProtectBeginUltra("WhipNexus_setPlainMode");
    socket.setPlainMode(enabled);
    VMProtectEnd();
}

void WhipNexus::setCertificatePinning(bool enabled, const byte* certHash) {
    VMProtectBeginUltra("WhipNexus_setCertificatePinning");
    certificatePinningEnabled = enabled;
    if (enabled && certHash) {
        SyscallManager::SecureMemCpy(pinnedCertificateHash, certHash, 32);
    }
    // Bind the proof to (enabled, hash). If a reverser later flips the bool
    // in memory without also forging this proof, performHandshake() detects
    // the desync and runs the cert check anyway.
    pinningProof = pinningProofOf(certificatePinningEnabled, pinnedCertificateHash);
    VMProtectEnd();
}

bool WhipNexus::connect(const char* host, u16 port) {
    VMProtectBeginUltra("WhipNexus_connect");
    if (!socket.connect(host, port)) {
        return false;
    }

    if (!performHandshake()) {
        socket.disconnect();
        return false;
    }

    // Bind the "connected" state to the real handshake-derived sessionKey.
    // RET-true patching of this function leaves sessionKey zeroed → proof
    // mismatches the all-zero fingerprint that isConnected() recomputes.
    // Third layer: WhipVM-encoded flag — disambiguates a memory-only patch
    // of `connected` + a guess on `connectedProof`.
    connected = true;
    connectedProof = connectionProofOf(sessionKey);
    connectedVmEncoded = encodeConnectedFlag(0u);
    return true;
    VMProtectEnd();
}

bool WhipNexus::isConnected() const {
    if (!connected) return false;
    if (!decodeConnectedIsTrue(connectedVmEncoded)) return false;
    // Recompute the proof from the live sessionKey. Defends against:
    //   - direct memory patch of `connected` (proof stays at the previous
    //     value — typically 0 if no handshake ever ran);
    //   - patch of `connectedProof` to a guessed value (must match the
    //     fingerprint of the actual sessionKey, which the attacker would
    //     need to read AND the formula they'd need to know);
    //   - patch of `connectedVmEncoded` — must reproduce the WhipVM cascade
    //     keyed on vm_runtime_key_stable() (PEB/TEB ASLR);
    //   - patch of the equality check (only single read site of `connected`,
    //     but other code paths still use sendPacket/receivePacket which
    //     fail if sessionKey is wrong → cascading failure).
    return connectionProofOf(sessionKey) == connectedProof;
}

void WhipNexus::disconnect() {
    VMProtectBeginUltra("WhipNexus_disconnect");
    stopEventLoop();
    socket.disconnect();
    connected = false;
    connectedProof = 0;
    connectedVmEncoded = encodeConnectedFlag(0xFFu);

    if (clientPrivateKey) {
        crypto.freeKeyHandle(clientPrivateKey);
        clientPrivateKey = nullptr;
    }
    VMProtectEnd();
}

bool WhipNexus::performHandshake() {
    VMProtectBeginUltra("WhipNexus_performHandshake");
    if (!crypto.generateEcdhKeyPair(clientPublicKey, &clientPublicKeyLength, &clientPrivateKey)) {
        return false;
    }

    ClientHelloData clientHello;
    clientHello.version = ProtocolConstants::VERSION;
    crypto.generateRandomBytes(clientHello.clientNonce, ProtocolConstants::CLIENT_NONCE_SIZE);
    clientHello.clientPublicKey = clientPublicKey;
    clientHello.clientPublicKeyLength = clientPublicKeyLength;

    Buffer helloPayload;
    if (!codec.encodeClientHello(clientHello, helloPayload)) {
        return false;
    }

    if (!sendPlainPacket(ProtocolConstants::OPCODE_CLIENT_HELLO, helloPayload)) {
        return false;
    }

    RawPacket responsePacket;
    if (!receivePacket(responsePacket)) {
        return false;
    }

    if (responsePacket.opcode != ProtocolConstants::OPCODE_SERVER_HELLO) {
        return false;
    }

    ServerHelloData serverHello;
    if (!codec.decodeServerHello(responsePacket.payload.data, responsePacket.payload.size, serverHello)) {
        return false;
    }

    if (serverHello.serverPublicKeyLength != 91) {
        return false;
    }

    // Tamper detection: a reverser flipping `certificatePinningEnabled` in
    // memory leaves `pinningProof` matching the previous (true + hash)
    // state. We force the cert check whenever pinning is explicitly enabled
    // OR the proof signals a desync — patching just the bool no longer
    // skips MITM defense.
    // Tamper detection: a reverser flipping `certificatePinningEnabled` in
    // memory leaves `pinningProof` matching the previous (true + hash)
    // state. We force the cert check whenever pinning is explicitly enabled
    // OR the proof signals a desync — patching just the bool no longer
    // skips MITM defense.
    bool expectedProofMatch = (pinningProof == pinningProofOf(certificatePinningEnabled, pinnedCertificateHash));
    bool runCertCheck = certificatePinningEnabled || !expectedProofMatch;

    if (runCertCheck) {
        if (!serverHello.serverPermanentPublicKey || serverHello.serverPermanentPublicKeyLength == 0) {
            return false;
        }

        if (!serverHello.signature || serverHello.signatureLength == 0 || serverHello.signatureLength > 73) {
            return false;
        }

        byte serverCertHash[32];
        if (!crypto.sha256Hash(serverHello.serverPermanentPublicKey,
                               serverHello.serverPermanentPublicKeyLength,
                               serverCertHash)) {
            return false;
        }

        int hashMatch = 0;
        for (int i = 0; i < 32; i++) {
            hashMatch |= serverCertHash[i] ^ pinnedCertificateHash[i];
        }

        if (hashMatch != 0) {
            return false;
        }

        if (!crypto.verifyEcdsa(serverHello.serverPermanentPublicKey,
                                serverHello.serverPermanentPublicKeyLength,
                                serverHello.serverPublicKey,
                                serverHello.serverPublicKeyLength,
                                serverHello.signature,
                                serverHello.signatureLength)) {
            return false;
        }
    }

    byte derivedKey[32];
    if (!crypto.deriveSessionKey(clientPrivateKey, serverHello.serverPublicKey,
                                  serverHello.serverPublicKeyLength,
                                  clientHello.clientNonce, serverHello.serverNonce,
                                  derivedKey)) {
        return false;
    }

    SyscallManager::SecureMemCpy(sendKey, derivedKey, 32);
    SyscallManager::SecureMemCpy(recvKey, derivedKey, 32);
    SyscallManager::SecureMemCpy(sessionKey, derivedKey, 32);
    SyscallManager::SecureZero(derivedKey, sizeof(derivedKey));

    return true;
    VMProtectEnd();
}

bool WhipNexus::registerHandler(u16 opcode, PacketHandler handler, void* context) {
    VMProtectBeginUltra("WhipNexus_registerHandler");
    if (handlerCount >= 256) { return false; }

    for (i32 i = 0; i < handlerCount; i++) {
        if (handlers[i].active && handlers[i].opcode == opcode) {
            handlers[i].handler = handler;
            handlers[i].context = context;
            return true;
        }
    }

    handlers[handlerCount].opcode = opcode;
    handlers[handlerCount].handler = handler;
    handlers[handlerCount].context = context;
    handlers[handlerCount].active = true;
    handlerCount++;
    return true;
    VMProtectEnd();
}

void WhipNexus::unregisterHandler(u16 opcode) {
    VMProtectBeginUltra("WhipNexus_unregisterHandler");
    for (i32 i = 0; i < handlerCount; i++) {
        if (handlers[i].active && handlers[i].opcode == opcode) {
            handlers[i].active = false;
            return;
        }
    }
    VMProtectEnd();
}

bool WhipNexus::startEventLoop() {
    VMProtectBeginUltra("WhipNexus_startEventLoop");
    if (running || !connected || !decodeConnectedIsTrue(connectedVmEncoded)) {
        VMProtectEnd();
        return false;
    }

    running = true;
    eventThread = SyscallManager::CreateThread(
        (void*)eventLoopThreadFunc, this, nullptr);

    return eventThread != nullptr;
    VMProtectEnd();
}

void WhipNexus::stopEventLoop() {
    VMProtectBeginUltra("WhipNexus_stopEventLoop");
    if (!running) {
        return;
    }

    running = false;
    socket.cancelPendingIo();

    if (eventThread) {
        // Cooperative path: NtCancelIoFile unblocks recv → loop checks
        // running=false → returns. ~µs in healthy case. 100ms is a generous
        // ceiling — anything past that is the thread stuck in a handler
        // callback or mid-decrypt; force-terminate so unload doesn't stall.
        // The thread's stack/state leaks, but unload tears down the DLL
        // pages anyway. Previous code used 500ms wait + NO terminate
        // fallback → the close ran on a still-alive thread, which kept
        // executing into freed pages.
        u32 wr = SyscallManager::WaitForThread(eventThread, 100);
        if (wr == WAIT_TIMEOUT) {
            SyscallManager::TerminateThread(eventThread);
            // Brief settle wait so the kernel marks the thread signaled
            // before we close the handle (avoids handle-close racing
            // against thread state finalization).
            SyscallManager::WaitForThread(eventThread, 50);
        }
        SyscallManager::CloseHandle(eventThread);
        eventThread = nullptr;
    }
    VMProtectEnd();
}

unsigned long WINAPI WhipNexus::eventLoopThreadFunc(void* param) {
    VMProtectBeginUltra("WhipNexus_eventLoopThreadFunc");
    WhipNexus* self = (WhipNexus*)param;
    self->eventLoopRun();
    return 0;
    VMProtectEnd();
}

void WhipNexus::eventLoopRun() {
    VMProtectBeginUltra("WhipNexus_eventLoopRun");
    while (running) {
        RawPacket packet;
        if (!receivePacket(packet)) {
            if (!running) break;
            running = false;
            connected = false;
            connectedProof = 0;
            connectedVmEncoded = encodeConnectedFlag(0xFFu);
            break;
        }

        // Les opcodes du handshake sont en clair (jamais reçus en boucle d'événements
        // en pratique, mais on garde la sécurité). Les autres sont chiffrés.
        if (packet.opcode != ProtocolConstants::OPCODE_CLIENT_HELLO &&
            packet.opcode != ProtocolConstants::OPCODE_SERVER_HELLO) {
            if (isNonceReplay(packet.nonce)) {
                continue;
            }

            Buffer plainPayload;
            if (!codec.decryptPacket(packet, recvKey, plainPayload)) {
                continue;
            }

            dispatchPacket(packet.opcode, plainPayload.data, plainPayload.size);
        } else {
            dispatchPacket(packet.opcode, packet.payload.data, packet.payload.size);
        }
    }
    VMProtectEnd();
}

void WhipNexus::dispatchPacket(u16 opcode, const byte* data, u32 length) {
    VMProtectBeginUltra("WhipNexus_dispatchPacket");

    for (i32 i = 0; i < handlerCount; i++) {
        if (handlers[i].active && handlers[i].opcode == opcode) {
            handlers[i].handler(opcode, data, length, handlers[i].context);
            return;
        }
    }

    VMProtectEnd();
}

bool WhipNexus::sendPacket(u16 opcode, const byte* data, u32 length) {
    VMProtectBeginUltra("WhipNexus_sendPacket");
    if (!connected || !decodeConnectedIsTrue(connectedVmEncoded)) { return false; }
    // Defence-in-depth: also verify the connection proof on every outbound
    // packet. A reverser flipping `connected` to true post-disconnect
    // (re-using a stale sessionKey) is caught here — the proof was reset
    // to 0 in disconnect() but sessionKey may still hold stale bytes.
    // Proof recompute matches only after a successful handshake.
    if (connectionProofOf(sessionKey) != connectedProof) { return false; }

    SyscallManager::EnterCriticalSection(sendMutex);

    Buffer payload(length);
    SyscallManager::SecureMemCpy(payload.data, data, length);
    payload.size = length;

    bool result = sendEncryptedPacket(opcode, payload);

    SyscallManager::LeaveCriticalSection(sendMutex);

    return result;
    VMProtectEnd();
}

bool WhipNexus::sendPacketInternal(const RawPacket& packet) {
    VMProtectBeginUltra("WhipNexus_sendPacketInternal");
    Buffer encodedPacket;
    if (!codec.encodeRawPacket(packet, encodedPacket)) {
        return false;
    }

    return socket.send(encodedPacket.data, encodedPacket.size);
    VMProtectEnd();
}

bool WhipNexus::receivePacket(RawPacket& packet) {
    byte headerBuf[ProtocolConstants::HEADER_SIZE];
    if (!socket.receiveExact(headerBuf, ProtocolConstants::HEADER_SIZE)) {
        return false;
    }

    const byte* ptr = headerBuf + 8;
    u32 payloadLen = ((u32)ptr[0] << 24) | ((u32)ptr[1] << 16) |
                     ((u32)ptr[2] << 8) | ((u32)ptr[3]);

    u32 totalSize = ProtocolConstants::HEADER_SIZE + payloadLen + ProtocolConstants::HMAC_SIZE;

    Buffer fullPacket(totalSize);
    SyscallManager::SecureMemCpy(fullPacket.data, headerBuf, ProtocolConstants::HEADER_SIZE);

    u32 remaining = payloadLen + ProtocolConstants::HMAC_SIZE;

    if (!socket.receiveExact(fullPacket.data + ProtocolConstants::HEADER_SIZE, remaining)) {
        return false;
    }

    fullPacket.size = totalSize;

    return codec.decodeRawPacket(fullPacket.data, fullPacket.size, packet);
}

bool WhipNexus::sendPlainPacket(u16 opcode, const Buffer& payload) {
    VMProtectBeginUltra("WhipNexus_sendPlainPacket");
    RawPacket packet;
    packet.opcode = opcode;
    SyscallManager::SecureZero(packet.nonce, ProtocolConstants::NONCE_SIZE);
    SyscallManager::SecureZero(packet.hmac, ProtocolConstants::HMAC_SIZE);
    packet.payload.resize(payload.size);
    SyscallManager::SecureMemCpy(packet.payload.data, payload.data, payload.size);

    return sendPacketInternal(packet);
    VMProtectEnd();
}

bool WhipNexus::sendEncryptedPacket(u16 opcode, const Buffer& payload) {
    VMProtectBeginUltra("WhipNexus_sendEncryptedPacket");
    RawPacket packet;
    if (!codec.createEncryptedPacket(opcode, payload, sendKey, packet)) {
        return false;
    }

    return sendPacketInternal(packet);
    VMProtectEnd();
}

bool WhipNexus::receiveDecryptedPacket(u16& opcodeOut, byte* dataOut, u32* dataLenOut, u32 maxLen) {
    VMProtectBeginUltra("WhipNexus_receiveDecryptedPacket");
    if (!connected || !decodeConnectedIsTrue(connectedVmEncoded)) {
        return false;
    }
    // Same defence as sendPacket: refuse to consume packets if the
    // connection proof doesn't match the live sessionKey. Decryption would
    // fail anyway on a tampered key, but rejecting earlier denies a
    // confused-deputy by-product (caller advances state machine assuming
    // encrypted handshake succeeded when it didn't).
    if (connectionProofOf(sessionKey) != connectedProof) {
        return false;
    }

    RawPacket packet;
    if (!receivePacket(packet)) {
        return false;
    }

    opcodeOut = packet.opcode;

    if (isNonceReplay(packet.nonce)) {
        return false;
    }

    Buffer plainPayload;
    if (!codec.decryptPacket(packet, recvKey, plainPayload)) {
        return false;
    }

    if (plainPayload.size > maxLen) {
        return false;
    }

    SyscallManager::SecureMemCpy(dataOut, plainPayload.data, plainPayload.size);
    *dataLenOut = plainPayload.size;

    return true;
    VMProtectEnd();
}

bool WhipNexus::generateRandomBytes(byte* output, u32 length) {
    VMProtectBeginUltra("WhipNexus_generateRandomBytes");
    return crypto.generateRandomBytes(output, length);
    VMProtectEnd();
}

bool WhipNexus::computeHmac(const byte* data, u32 dataLength, byte* hmacOut) {
    VMProtectBeginUltra("WhipNexus_computeHmac");
    // sessionKey est la clé permanente de la session (pas la clé d'envoi rotative).
    return crypto.hmacSha256(data, dataLength, sessionKey, 32, hmacOut);
    VMProtectEnd();
}

bool WhipNexus::decryptFilePayload(const byte* nonce, u32 nonceLen,
                                   const byte* ciphertextWithTag, u32 ciphertextLen,
                                   byte* plaintextOut, u32* plaintextLenOut) {
    VMProtectBeginUltra("WhipNexus_decryptFilePayload");
    // Le serveur encrypte chaque file-chunk en AES-256-GCM avec sessionKey
    // (BucketService.readAndEncryptChunk) et émet `nonce(12) || ct || tag(16)`.
    // CryptoService.decrypt attend ciphertext = ct||tag concaténés, ce que
    // l'appelant nous fournit déjà.
    if (!nonce || nonceLen != 12 || !ciphertextWithTag || ciphertextLen < 16 ||
        !plaintextOut || !plaintextLenOut) {
        return false;
    }
    return crypto.decrypt(ciphertextWithTag, ciphertextLen,
                          sessionKey, 32,
                          nonce, nonceLen,
                          plaintextOut, plaintextLenOut);
    VMProtectEnd();
}

void WhipNexus::lockIO() {
    SyscallManager::EnterCriticalSection(ioMutex);
}

void WhipNexus::unlockIO() {
    SyscallManager::LeaveCriticalSection(ioMutex);
}
