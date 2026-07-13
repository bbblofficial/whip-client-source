package fr.whip.bot.data.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "ticket_messages", indexes = {
        @Index(name = "idx_tm_ticket_uid", columnList = "ticket_uid"),
        @Index(name = "idx_tm_ts",         columnList = "ts")
})
public class TicketMessage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(name = "ticket_uid", length = 20, nullable = false)
    private String ticketUserId;

    @Column(name = "sender_id", length = 20, nullable = false)
    private String senderId;

    @Column(name = "sender_name", length = 64, nullable = false)
    private String senderName;

    @Column(name = "is_staff", nullable = false)
    private boolean staff;

    @Column(name = "content", columnDefinition = "TEXT", nullable = false)
    private String content;

    @Column(name = "ts", nullable = false)
    private Instant timestamp;

    public TicketMessage() {}

    public TicketMessage(String ticketUserId, String senderId, String senderName, boolean staff, String content) {
        this.ticketUserId = ticketUserId;
        this.senderId     = senderId;
        this.senderName   = senderName;
        this.staff        = staff;
        this.content      = content;
        this.timestamp    = Instant.now();
    }

    public long getId()            { return id; }
    public String getTicketUserId(){ return ticketUserId; }
    public String getSenderId()    { return senderId; }
    public String getSenderName()  { return senderName; }
    public boolean isStaff()       { return staff; }
    public String getContent()     { return content; }
    public Instant getTimestamp()  { return timestamp; }
}
