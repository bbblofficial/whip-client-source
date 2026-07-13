package fr.whip.bot.data.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "tickets")
public class TicketEntity {

    @Id
    @Column(name = "user_discord_id")
    private String userDiscordId;

    @Column(name = "staff_channel_id", nullable = false)
    private String staffChannelId;

    @Column(name = "reason")
    private String reason;

    @Column(name = "last_activity")
    private Instant lastActivity;

    @Column(name = "opened_at")
    private Instant openedAt;

    @Column(name = "awaiting_user_reply")
    private boolean awaitingUserReply;

    @Column(name = "reminder_sent")
    private boolean reminderSent;

    // 0 = aucun rappel envoyé, 1 = rappel 1h, 2 = rappel 12h, 3 = rappel 24h.
    // Remis à 0 dès que le client renvoie un message (le compteur repart).
    // Integer (et non int) : la colonne ajoutée par Hibernate sur les tickets déjà
    // existants vaut NULL ; un int primitif ferait planter le chargement (findAll).
    @Column(name = "staff_reminder_stage")
    private Integer staffReminderStage;

    @Column(name = "detected_language")
    private String detectedLanguage;

    public TicketEntity() {
    }

    public TicketEntity(String userDiscordId, String staffChannelId, String reason, Instant lastActivity,
            Instant openedAt) {
        this.userDiscordId = userDiscordId;
        this.staffChannelId = staffChannelId;
        this.reason = reason;
        this.lastActivity = lastActivity;
        this.openedAt = openedAt;
        this.awaitingUserReply = false;
        this.reminderSent = false;
        this.staffReminderStage = 0;
    }

    public String getUserDiscordId() {
        return userDiscordId;
    }

    public void setUserDiscordId(String userDiscordId) {
        this.userDiscordId = userDiscordId;
    }

    public String getStaffChannelId() {
        return staffChannelId;
    }

    public void setStaffChannelId(String staffChannelId) {
        this.staffChannelId = staffChannelId;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public Instant getLastActivity() {
        return lastActivity;
    }

    public void setLastActivity(Instant lastActivity) {
        this.lastActivity = lastActivity;
    }

    public boolean isAwaitingUserReply() {
        return awaitingUserReply;
    }

    public void setAwaitingUserReply(boolean awaitingUserReply) {
        this.awaitingUserReply = awaitingUserReply;
    }

    public Instant getOpenedAt() {
        return openedAt;
    }

    public void setOpenedAt(Instant openedAt) {
        this.openedAt = openedAt;
    }

    public boolean isReminderSent() {
        return reminderSent;
    }

    public void setReminderSent(boolean reminderSent) {
        this.reminderSent = reminderSent;
    }

    public int getStaffReminderStage() {
        return staffReminderStage == null ? 0 : staffReminderStage;
    }

    public void setStaffReminderStage(int staffReminderStage) {
        this.staffReminderStage = staffReminderStage;
    }

    public String getDetectedLanguage() {
        return detectedLanguage;
    }

    public void setDetectedLanguage(String detectedLanguage) {
        this.detectedLanguage = detectedLanguage;
    }
}
