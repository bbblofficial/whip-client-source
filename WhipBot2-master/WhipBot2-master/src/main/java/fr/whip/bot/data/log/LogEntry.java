package fr.whip.bot.data.log;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "logs", indexes = {
        @Index(name = "idx_logs_ts",       columnList = "ts"),
        @Index(name = "idx_logs_cat_ts",   columnList = "cat, ts"),
        @Index(name = "idx_logs_uid",      columnList = "uid")
})
public class LogEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Enumerated(EnumType.ORDINAL)
    @Column(name = "lvl", nullable = false, columnDefinition = "SMALLINT")
    private LogLevel level;

    @Enumerated(EnumType.ORDINAL)
    @Column(name = "cat", nullable = false, columnDefinition = "SMALLINT")
    private LogCategory category;

    @Column(name = "uid", length = 20)
    private String userId;

    @Column(name = "msg", nullable = false, columnDefinition = "TEXT")
    private String message;

    @Column(name = "ts", nullable = false)
    private Instant timestamp;

    public LogEntry() {}

    public LogEntry(LogLevel level, LogCategory category, String userId, String message) {
        this.level     = level;
        this.category  = category;
        this.userId    = userId;
        this.message   = message != null && message.length() > 500 ? message.substring(0, 500) : message;
        this.timestamp = Instant.now();
    }

    public long getId()             { return id; }
    public LogLevel getLevel()      { return level; }
    public LogCategory getCategory(){ return category; }
    public String getUserId()       { return userId; }
    public String getMessage()      { return message; }
    public Instant getTimestamp()   { return timestamp; }
}
