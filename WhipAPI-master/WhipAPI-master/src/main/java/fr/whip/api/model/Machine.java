package fr.whip.api.model;

import fr.whip.api.storage.IIdentifiable;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "machines")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Machine implements IIdentifiable {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String hwid;

    @Column(name = "pc_name")
    private String pcName;

    private String os;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_seen_at")
    private Instant lastSeenAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "gpu_name")
    private String gpuName;

    @Column(name = "cpu_brand")
    private String cpuBrand;

    @Column(name = "ram_hex")
    private String ramHex;

    @Column(name = "board_model")
    private String boardModel;

    @Column(name = "screen_info")
    private String screenInfo;

    @Column(name = "storage_info")
    private String storageInfo;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        lastSeenAt = Instant.now();
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public void updateLastSeen() {
        this.lastSeenAt = Instant.now();
    }

    @Override
    public String toString() {
        return "Machine{" +
                "id=" + id +
                ", user=" + user +
                ", hwid='" + hwid + '\'' +
                ", pcName='" + pcName + '\'' +
                ", os='" + os + '\'' +
                ", createdAt=" + createdAt +
                ", lastSeenAt=" + lastSeenAt +
                ", revokedAt=" + revokedAt +
                '}';
    }
}