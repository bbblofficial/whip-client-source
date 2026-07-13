package fr.whip.api.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "used_nonces")
@Getter
@Setter
@NoArgsConstructor
public class UsedNonce {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "nonce_hash", nullable = false, unique = true)
    private String nonceHash;

    @Column(name = "session_id")
    private UUID sessionId;

    @Column(name = "used_at", nullable = false)
    private Instant usedAt;

    public UsedNonce(String nonceHash, UUID sessionId) {
        this.nonceHash = nonceHash;
        this.sessionId = sessionId;
        this.usedAt = Instant.now();
    }

    @Override
    public String toString() {
        return "UsedNonce{" +
                "id=" + id +
                ", nonceHash='" + nonceHash + '\'' +
                ", sessionId=" + sessionId +
                ", usedAt=" + usedAt +
                '}';
    }
}