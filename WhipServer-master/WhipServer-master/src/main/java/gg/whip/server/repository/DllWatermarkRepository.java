package gg.whip.server.repository;

import gg.whip.server.model.DllWatermark;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface DllWatermarkRepository extends JpaRepository<DllWatermark, UUID> {

    /** Look up by the 36-char UUID embedded in the DLL bytes. */
    Optional<DllWatermark> findBySessionUuid(String sessionUuid);
}
