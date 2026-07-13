package fr.whip.api.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "sessions")
@Getter
@Setter
@NoArgsConstructor
public class Session {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "license_id", nullable = false)
    private License license;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "machine_id", nullable = false)
    private Machine machine;

    @Column(nullable = false)
    private String ip;

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @Column(name = "session_key_hash", nullable = false)
    private String sessionKeyHash;

    @Column(name = "started_at", nullable = false, updatable = false)
    private Instant startedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "ended_at")
    private Instant endedAt;

    @Column(name = "last_heartbeat_at")
    private Instant lastHeartbeatAt;

    @PrePersist
    protected void onCreate() {
        startedAt = Instant.now();
        lastHeartbeatAt = Instant.now();
    }

    public boolean isActive() {
        return endedAt == null && Instant.now().isBefore(expiresAt);
    }

    public void end() {
        this.endedAt = Instant.now();
    }

    public void refreshHeartbeat() {
        this.lastHeartbeatAt = Instant.now();
    }

    @Override
    public String toString() {
        return "Session{" +
                "id=" + id +
                ", license=" + license +
                ", machine=" + machine +
                ", ip='" + ip + '\'' +
                ", tokenHash='" + tokenHash + '\'' +
                ", startedAt=" + startedAt +
                ", expiresAt=" + expiresAt +
                ", endedAt=" + endedAt +
                ", lastHeartbeatAt=" + lastHeartbeatAt +
                '}';
    }
}