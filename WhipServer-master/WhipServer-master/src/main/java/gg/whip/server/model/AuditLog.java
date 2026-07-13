package gg.whip.server.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/**
 * Maps the existing {@code audit_logs} table (shared with the admin panel).
 *
 * Convention: when {@code adminId} AND {@code entityId} are both null, the row
 * is a SYSTEM event (server start/stop, client connect/disconnect, error,
 * auth…) with no admin actor and no target entity. Admin actions written by
 * the website keep both set.
 */
@Entity
@Table(name = "audit_logs")
@Getter
@Setter
@NoArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, columnDefinition = "text")
    private String action;

    @Column(nullable = false, columnDefinition = "text")
    private String entity;

    @Column(columnDefinition = "text")
    private String details;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "admin_id")
    private UUID adminId;

    @Column(name = "entity_id")
    private UUID entityId;

    /** Source IP for client-attributed events (auth, download, connection). */
    @Column(columnDefinition = "text")
    private String ip;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = Instant.now();
    }
}
