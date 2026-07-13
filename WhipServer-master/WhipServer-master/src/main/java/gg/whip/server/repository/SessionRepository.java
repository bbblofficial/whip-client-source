package gg.whip.server.repository;

import fr.whip.api.model.License;
import fr.whip.api.model.Machine;
import fr.whip.api.model.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SessionRepository extends JpaRepository<Session, UUID> {

    Optional<Session> findByTokenHash(String tokenHash);

    List<Session> findByLicenseAndEndedAtIsNull(License license);

    @Query("SELECT COUNT(s) FROM Session s WHERE s.license = :license AND s.endedAt IS NULL AND s.expiresAt > :now")
    long countActiveSessions(License license, Instant now);

    @Query("SELECT COUNT(s) FROM Session s WHERE s.machine = :machine AND s.endedAt IS NULL AND s.expiresAt > :now")
    long countActiveSessionsByMachine(Machine machine, Instant now);

    @Modifying
    @Query("UPDATE Session s SET s.endedAt = :now WHERE s.expiresAt < :now AND s.endedAt IS NULL")
    int expireOldSessions(Instant now);

    @Modifying
    @Query("UPDATE Session s SET s.endedAt = :now WHERE s.lastHeartbeatAt < :timeout AND s.endedAt IS NULL")
    int expireInactiveSessions(Instant now, Instant timeout);

    /**
     * findById with license + license.user + license.product + machine
     * eagerly fetched in one query. HeartbeatHandler swaps the cached
     * ClientSession.dbSession for this fresh row each tick — without
     * the JOIN FETCHes, downstream handlers (ConfigHandler etc.) hit
     * LazyInitializationException when dereferencing license.user
     * outside the heartbeat transaction.
     */
    @Query("""
            SELECT s FROM Session s
            LEFT JOIN FETCH s.license l
            LEFT JOIN FETCH l.user
            LEFT JOIN FETCH l.product
            LEFT JOIN FETCH s.machine
            WHERE s.id = :id
            """)
    Optional<Session> findByIdWithGraph(UUID id);
}