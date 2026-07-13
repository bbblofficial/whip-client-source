package fr.whip.bot.data.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "ticket_bans")
public class TicketBanEntity {

    @Id
    @Column(name = "user_discord_id")
    private String userDiscordId;

    @Column(name = "reason")
    private String reason;

    @Column(name = "banned_by")
    private String bannedBy;

    @Column(name = "banned_at")
    private Instant bannedAt;

    public TicketBanEntity() {
    }

    public TicketBanEntity(String userDiscordId, String reason, String bannedBy, Instant bannedAt) {
        this.userDiscordId = userDiscordId;
        this.reason = reason;
        this.bannedBy = bannedBy;
        this.bannedAt = bannedAt;
    }

    public String getUserDiscordId() {
        return userDiscordId;
    }

    public void setUserDiscordId(String userDiscordId) {
        this.userDiscordId = userDiscordId;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getBannedBy() {
        return bannedBy;
    }

    public void setBannedBy(String bannedBy) {
        this.bannedBy = bannedBy;
    }

    public Instant getBannedAt() {
        return bannedAt;
    }

    public void setBannedAt(Instant bannedAt) {
        this.bannedAt = bannedAt;
    }
}
