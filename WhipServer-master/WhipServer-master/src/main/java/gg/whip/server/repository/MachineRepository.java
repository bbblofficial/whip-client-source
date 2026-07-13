package gg.whip.server.repository;

import fr.whip.api.model.Machine;
import fr.whip.api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface MachineRepository extends JpaRepository<Machine, UUID> {

    Optional<Machine> findByUserAndHwid(User user, String hwid);

    Optional<Machine> findByHwidAndRevokedAtIsNull(String hwid);

    @Query("SELECT m FROM Machine m JOIN FETCH m.user WHERE m.hwid = :hwid AND m.revokedAt IS NULL")
    Optional<Machine> findByHwidNotRevokedWithUser(@Param("hwid") String hwid);

    @Query("SELECT m FROM Machine m JOIN FETCH m.user WHERE m.hwid = :hwid ORDER BY m.createdAt DESC")
    List<Machine> findByHwidWithUser(@Param("hwid") String hwid);

    List<Machine> findByUser(User user);

    List<Machine> findByUserAndRevokedAtIsNull(User user);

    boolean existsByUserAndHwid(User user, String hwid);
}