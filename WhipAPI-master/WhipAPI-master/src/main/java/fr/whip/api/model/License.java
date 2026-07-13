package fr.whip.api.model;

import fr.whip.api.storage.IIdentifiable;
import fr.whip.api.type.PostgreSQLEnumType;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.Type;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "licenses")
@Getter
@Setter
@NoArgsConstructor
public class License implements IIdentifiable {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "license_key", nullable = false, unique = true)
    private String licenseKey;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id")
    private User user;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;

    @Type(PostgreSQLEnumType.class)
    @Column(name = "status", nullable = false)
    private LicenseStatus status = LicenseStatus.active;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
    }

    public boolean isValid() {
        if (status != LicenseStatus.active) return false;
        return expiresAt == null || !Instant.now().isAfter(expiresAt);
    }

    @Override
    public String toString() {
        return "License{" +
                "id=" + id +
                ", licenseKey='" + licenseKey + '\'' +
                ", status=" + status +
                ", createdAt=" + createdAt +
                ", expiresAt=" + expiresAt +
                '}';
    }
}