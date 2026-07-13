package gg.whip.server.service;

import fr.whip.api.model.License;
import fr.whip.api.model.Machine;
import fr.whip.api.model.User;
import lombok.Data;

import java.time.Instant;

@Data
public class TemporaryClientToken {
    private byte[] token;
    // Single-use attestation token presented by the client in CLIENT_AUTH
    // to prove the loader→client chain. Generated server-side at PRODUCT_SELECT,
    // forwarded to the client through the loader's IPC, then consumed exactly once.
    private byte[] clientAttestationToken;
    private boolean attestationConsumed;
    // Phase 1: copy of download.authSalt at the moment we issued this token.
    // Used by ClientAuthHandler to validate the loader's auth_tag forwarded
    // by the client (loader computed HMAC(authSalt, tempToken)).
    private byte[] authSalt;
    // Phase 2: copy of download.algoSeed at issuance time.
    private byte[] algoSeed;
    // Phase 3: copy of download.expectedFingerprint at issuance time.
    private byte[] expectedFingerprint;
    private User user;
    private License license;
    private Machine machine;
    private String productCode;
    private String hwid;
    private String ipAddress;
    private Instant createdAt;
    private Instant expiresAt;

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
