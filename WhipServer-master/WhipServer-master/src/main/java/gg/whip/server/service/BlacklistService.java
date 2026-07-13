package gg.whip.server.service;

import fr.whip.api.model.User;
import gg.whip.server.data.Blacklist;
import gg.whip.server.repository.BlacklistRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class BlacklistService {

    private static final Logger log = LoggerFactory.getLogger(BlacklistService.class);

    private final BlacklistRepository blacklistRepository;

    private final Set<UUID> blacklistedUserIds = ConcurrentHashMap.newKeySet();

    @PostConstruct
    void init() {
        refreshCache();
        log.info("Blacklist service initialized — {} users cached", blacklistedUserIds.size());
    }

    public boolean isBlacklisted(User user) {
        return blacklistedUserIds.contains(user.getId());
    }

    public boolean isBlacklisted(UUID userId) {
        return blacklistedUserIds.contains(userId);
    }

    @Transactional
    public void blacklist(User user, String reason, Duration duration, String createdBy) {
        Optional<Blacklist> existing = blacklistRepository.findActiveByUser(user, Instant.now());
        if (existing.isPresent()) {
            log.debug("User {} already blacklisted, skipping", user.getUsername());
            return;
        }

        Blacklist entry = Blacklist.builder()
                .user(user)
                .reason(reason)
                .expiresAt(duration != null ? Instant.now().plus(duration) : null)
                .createdBy(createdBy)
                .build();

        blacklistRepository.save(entry);
        blacklistedUserIds.add(user.getId());
        log.info("Blacklisted user {} — reason: {}, duration: {}, by: {}", user.getUsername(), reason, duration, createdBy);
    }

    @Transactional
    public void unblacklist(User user) {
        blacklistRepository.deleteByUser(user);
        blacklistedUserIds.remove(user.getId());
        log.info("Unblacklisted user {}", user.getUsername());
    }

    @Scheduled(fixedRateString = "${server.blacklist.cache-refresh-ms:30000}")
    @Transactional(readOnly = true)
    public void refreshCache() {
        Set<UUID> active = ConcurrentHashMap.newKeySet();
        blacklistRepository.findAll().stream()
                .filter(Blacklist::isActive)
                .forEach(entry -> active.add(entry.getUser().getId()));

        blacklistedUserIds.clear();
        blacklistedUserIds.addAll(active);
        log.debug("Blacklist cache refreshed — {} entries", blacklistedUserIds.size());
    }

    @Scheduled(fixedRateString = "${server.blacklist.cleanup-interval-ms:3600000}")
    @Transactional
    public void cleanupExpired() {
        int removed = blacklistRepository.deleteExpired(Instant.now());
        if (removed > 0) {
            log.info("Cleaned up {} expired blacklist entries", removed);
            refreshCache();
        }
    }
}
