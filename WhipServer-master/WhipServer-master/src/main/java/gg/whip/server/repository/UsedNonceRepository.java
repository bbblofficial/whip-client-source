package gg.whip.server.repository;

import fr.whip.api.model.UsedNonce;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.UUID;

public interface UsedNonceRepository extends JpaRepository<UsedNonce, UUID> {

    boolean existsByNonceHash(String nonceHash);

    @Modifying
    @Query("DELETE FROM UsedNonce n WHERE n.usedAt < :before")
    int deleteOldNonces(Instant before);
}