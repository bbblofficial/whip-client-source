#pragma optimize("", off)
#include "whipnexus/Packet.h"
#include "whipnexus/SyscallManager.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

RawPacket::RawPacket() : opcode(ProtocolConstants::OPCODE_CLIENT_HELLO) {
    SyscallManager::SecureMemSet(nonce, 0, sizeof(nonce));
    SyscallManager::SecureMemSet(hmac, 0, sizeof(hmac));
}

RawPacket::~RawPacket() {
    clear();
}

void RawPacket::clear() {
    payload.clear();
}

ClientHelloData::ClientHelloData()
    : version(ProtocolConstants::VERSION), clientPublicKey(nullptr), clientPublicKeyLength(0) {
    SyscallManager::SecureMemSet(clientNonce, 0, sizeof(clientNonce));
}

ClientHelloData::~ClientHelloData() {
}

ServerHelloData::ServerHelloData() : serverPublicKey(nullptr), serverPublicKeyLength(0),
                                      serverPermanentPublicKey(nullptr), serverPermanentPublicKeyLength(0),
                                      signature(nullptr), signatureLength(0) {
    SyscallManager::SecureMemSet(serverNonce, 0, sizeof(serverNonce));
    SyscallManager::SecureMemSet(tempSessionId, 0, sizeof(tempSessionId));
}

ServerHelloData::~ServerHelloData() {
    if (serverPublicKey) {
        SyscallManager::GetWrappers()->HeapFree(serverPublicKey);
        serverPublicKey = nullptr;
    }
    if (serverPermanentPublicKey) {
        SyscallManager::GetWrappers()->HeapFree(serverPermanentPublicKey);
        serverPermanentPublicKey = nullptr;
    }
    if (signature) {
        SyscallManager::GetWrappers()->HeapFree(signature);
        signature = nullptr;
    }
}
