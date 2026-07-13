package gg.whip.server.repository;

import gg.whip.server.model.MachineHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface MachineHistoryRepository extends JpaRepository<MachineHistory, UUID> {
    List<MachineHistory> findByMachineIdOrderByChangedAtDesc(UUID machineId);
}
