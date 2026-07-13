package gg.whip.server.service;

import fr.whip.api.model.Machine;
import fr.whip.api.model.User;
import gg.whip.server.repository.MachineRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MachineService {

    private final MachineRepository machineRepository;

    @Transactional(readOnly = true)
    public Optional<Machine> findByUserAndHwid(User user, String hwid) {
        return machineRepository.findByUserAndHwid(user, hwid);
    }

    @Transactional(readOnly = true)
    public List<Machine> findActiveMachines(User user) {
        return machineRepository.findByUserAndRevokedAtIsNull(user);
    }

    @Transactional(readOnly = true)
    public boolean isHwidRegistered(User user, String hwid) {
        return machineRepository.existsByUserAndHwid(user, hwid);
    }

    @Transactional
    public Machine registerMachine(User user, String hwid, String pcName, String os,
                                   String gpuName, String cpuBrand, String ramHex,
                                   String boardModel, String screenInfo, String storageInfo) {
        Machine machine = Machine.builder()
                .user(user)
                .hwid(hwid)
                .pcName(pcName)
                .os(os)
                .gpuName(blankToNull(gpuName))
                .cpuBrand(blankToNull(cpuBrand))
                .ramHex(blankToNull(ramHex))
                .boardModel(blankToNull(boardModel))
                .screenInfo(blankToNull(screenInfo))
                .storageInfo(blankToNull(storageInfo))
                .lastSeenAt(Instant.now())
                .build();
        return machineRepository.save(machine);
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }

    @Transactional
    public void updateLastSeen(Machine machine) {
        machine.setLastSeenAt(Instant.now());
        machineRepository.save(machine);
    }

    @Transactional
    public void revokeMachine(Machine machine) {
        machine.setRevokedAt(Instant.now());
        machineRepository.save(machine);
    }
}