package fr.whip.bot.data.log;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Maps the shared {@code audit_logs} table (the admin panel's journal).
 *
 * The bot writes SYSTEM events here (startup, shutdown, errors): admin_id and
 * entity_id stay null, which the panel renders as "Système". This is separate
 * from the bot's own {@link LogEntry} ("logs" table) used for Discord activity.
 */
@Entity
@Table(name = "audit_logs")
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

    public AuditLog() {}

    public AuditLog(String action, String entity, String details) {
        this.action = action;
        this.entity = entity;
        this.details = details != null && details.length() > 1000 ? details.substring(0, 1000) : details;
        this.createdAt = Instant.now();
    }

    public UUID getId()         { return id; }
    public String getAction()   { return action; }
    public String getEntity()   { return entity; }
    public String getDetails()  { return details; }
    public Instant getCreatedAt() { return createdAt; }
    public UUID getAdminId()    { return adminId; }
    public UUID getEntityId()   { return entityId; }

    public void setEntityId(UUID entityId) { this.entityId = entityId; }
}
