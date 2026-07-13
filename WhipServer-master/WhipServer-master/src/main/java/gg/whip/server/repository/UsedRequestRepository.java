package gg.whip.server.repository;

import fr.whip.api.model.UsedRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.UUID;

public interface UsedRequestRepository extends JpaRepository<UsedRequest, UUID> {

    @Modifying
    @Query("DELETE FROM UsedRequest r WHERE r.usedAt < :before")
    int deleteOldRequests(Instant before);
}