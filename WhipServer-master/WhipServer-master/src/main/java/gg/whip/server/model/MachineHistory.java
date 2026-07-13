package gg.whip.server.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "machine_histories", indexes = {
    @Index(name = "idx_mhist_machine",  columnList = "machine_id"),
    @Index(name = "idx_mhist_changed",  columnList = "changed_at")
})
@Getter
@Setter
@NoArgsConstructor
public class MachineHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "machine_id", nullable = false)
    private UUID machineId;

    @Column(name = "field_name", nullable = false, length = 64)
    private String fieldName;

    @Column(name = "old_value", length = 512)
    private String oldValue;

    @Column(name = "new_value", length = 512)
    private String newValue;

    @Column(name = "changed_at", nullable = false)
    private Instant changedAt;

    public MachineHistory(UUID machineId, String fieldName, String oldValue, String newValue) {
        this.machineId  = machineId;
        this.fieldName  = fieldName;
        this.oldValue   = oldValue;
        this.newValue   = newValue;
        this.changedAt  = Instant.now();
    }
}
