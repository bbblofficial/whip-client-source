package fr.whip.api.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "used_requests")
@Getter
@Setter
@NoArgsConstructor
public class UsedRequest {

    @Id
    private UUID id;

    @Column(name = "session_id", nullable = false)
    private UUID sessionId;

    @Column(name = "used_at", nullable = false)
    private Instant usedAt;

    public UsedRequest(UUID requestId, UUID sessionId) {
        this.id = requestId;
        this.sessionId = sessionId;
        this.usedAt = Instant.now();
    }

    @Override
    public String toString() {
        return "UsedRequest{" +
                "id=" + id +
                ", sessionId=" + sessionId +
                ", usedAt=" + usedAt +
                '}';
    }
}