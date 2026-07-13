package gg.whip.server.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/**
 * Per-download watermark embedded in WhipClient.dll bytes before encryption.
 *
 * <p>The 32-byte slot in the DLL's .rdata is overwritten by the server with:
 * <pre>
 *   magic[8]              = 'W','H','P','_','W','M','0','1'
 *   sessionUuidBytes[16]  = random 128-bit session id
 *   hmacTrunc[8]          = first 8 bytes of HMAC-SHA256(secret, sessionUuidBytes || userId || hwid)
 * </pre>
 *
 * If a copy of the DLL ever surfaces publicly, grepping the magic and looking
 * up the {@code sessionUuid} here identifies the exact session that received
 * it — and therefore the user, HWID, IP, Discord id to ban.
 *
 * <p>See {@code WhipLoader/DUMP_THREAT_MODEL.md §5.3}.
 */
@Entity
@Table(name = "dll_watermarks", indexes = {
    @Index(name = "idx_watermark_session_uuid", columnList = "session_uuid", unique = true),
    @Index(name = "idx_watermark_user", columnList = "user_id"),
    @Index(name = "idx_watermark_created", columnList = "created_at")
})
@Getter
@Setter
@NoArgsConstructor
public class DllWatermark {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "session_uuid", nullable = false, unique = true, length = 36)
    private String sessionUuid;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "discord_id")
    private String discordId;

    @Column(name = "hwid", length = 128)
    private String hwid;

    @Column(name = "ip", length = 45)
    private String ip;

    @Column(name = "pc_name", length = 128)
    private String pcName;

    @Column(name = "hmac_hex", length = 32)
    private String hmacHex;

    @Column(name = "download_id")
    private UUID downloadId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public DllWatermark(String sessionUuid, UUID userId, String discordId,
                        String hwid, String ip, String pcName, String hmacHex,
                        UUID downloadId) {
        this.sessionUuid = sessionUuid;
        this.userId = userId;
        this.discordId = discordId;
        this.hwid = hwid;
        this.ip = ip;
        this.pcName = pcName;
        this.hmacHex = hmacHex;
        this.downloadId = downloadId;
        this.createdAt = Instant.now();
    }
}
