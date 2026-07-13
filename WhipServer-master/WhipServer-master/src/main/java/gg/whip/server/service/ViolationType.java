package gg.whip.server.service;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ViolationType {

    NONCE_REPLAY(30),
    HMAC_FAILED(40),
    DECRYPTION_FAILED(25),
    INVALID_TIMESTAMP(15),
    REQUEST_REPLAY(30),
    REPLAY_DETECTED(30),
    INVALID_PACKET(25),
    IP_MISMATCH(35),
    HWID_MISMATCH(50),
    INVALID_TOKEN(20),
    AUTH_FAILED(20),
    RATE_LIMIT_EXCEEDED(10),
    INVALID_STATE(50),
    CHALLENGE_FAILED(35),
    REVERSE_DETECTED(80),
    // Tampered loader detection. Default block threshold = 100, weight 50 →
    // 2 strikes = score 100 → instant auto-ban. A legit user never produces
    // this (their loader is intact); 1 strike could be a network/build glitch
    // but 2 in the same window is a clear attack signal.
    AUTH_TAG_MISMATCH(50),
    // Same logic for the single-use attestation token: replay/forge → 2 hits = ban.
    ATTESTATION_TOKEN_INVALID(50);

    private final int weight;
}
