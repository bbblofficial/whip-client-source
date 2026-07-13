package fr.whip.api.model;

import fr.whip.api.storage.IIdentifiable;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "downloads")
@Getter
@Setter
@NoArgsConstructor
public class Download implements IIdentifiable {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "download_id", nullable = false, unique = true, length = 32)
    private String downloadId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id")
    private Product product;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "downloaded_at", nullable = false)
    private Instant downloadedAt;

    @Column(name = "first_used_at")
    private Instant firstUsedAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "use_count", nullable = false)
    private int useCount = 0;

    @Column(nullable = false)
    private boolean revoked = false;

    @Column(name = "revoke_reason", length = 255)
    private String revokeReason;

    // Per-download HMAC salt baked into the loader overlay. The loader uses
    // it as the key for Sentinel::deriveAuthTag(buf, len, salt) on the 3
    // anti-debug call sites; the server recomputes and rejects on mismatch.
    @Column(name = "auth_salt", length = 16)
    private byte[] authSalt;

    // Phase 2: per-download algorithm seed mixed into the HMAC key derivation
    // → key_material = SHA-256(authSalt || algoSeed). Reversing one user's
    // loader does not yield the algo for any other user — crack non-portable.
    @Column(name = "algo_seed", length = 32)
    private byte[] algoSeed;

    // Phase 3: SHA-256 of the patched loader's .text section. The loader
    // recomputes at runtime and mixes it into the HMAC key. Any byte patched
    // anywhere in .text → runtime fingerprint differs from this stored
    // expected value → tag mismatch → reject. Closes "patch the function
    // body" attacks (NOPs, RET hijacks, etc.).
    @Column(name = "expected_fingerprint", length = 32)
    private byte[] expectedFingerprint;

    @PrePersist
    protected void onCreate() {
        downloadedAt = Instant.now();
    }

    public void incrementUseCount() {
        useCount++;
    }

    @Override
    public String toString() {
        return "Download{" +
                "id=" + id +
                ", downloadId='" + downloadId + '\'' +
                ", user=" + user +
                ", product=" + product +
                ", ipAddress='" + ipAddress + '\'' +
                ", downloadedAt=" + downloadedAt +
                ", firstUsedAt=" + firstUsedAt +
                ", lastUsedAt=" + lastUsedAt +
                ", useCount=" + useCount +
                ", revoked=" + revoked +
                '}';
    }
}