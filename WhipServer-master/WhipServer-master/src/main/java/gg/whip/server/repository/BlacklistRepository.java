package gg.whip.server.repository;

import fr.whip.api.model.User;
import gg.whip.server.data.Blacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface BlacklistRepository extends JpaRepository<Blacklist, UUID> {

    @Query("SELECT b FROM Blacklist b WHERE b.user = :user AND (b.expiresAt IS NULL OR b.expiresAt > :now)")
    Optional<Blacklist> findActiveByUser(User user, Instant now);

    @Query("SELECT b FROM Blacklist b WHERE b.user.id = :userId AND (b.expiresAt IS NULL OR b.expiresAt > :now)")
    Optional<Blacklist> findActiveByUserId(UUID userId, Instant now);

    List<Blacklist> findByUser(User user);

    @Modifying
    @Query("DELETE FROM Blacklist b WHERE b.expiresAt IS NOT NULL AND b.expiresAt < :now")
    int deleteExpired(Instant now);

    void deleteByUser(User user);
}
