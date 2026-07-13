package gg.whip.server.service;

import fr.whip.api.model.User;
import gg.whip.server.config.ServerProperties;
import gg.whip.server.data.ClientSession;
import io.netty.channel.Channel;
import io.netty.util.AttributeKey;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class AnomalyDetectionService {

    private static final Logger log = LoggerFactory.getLogger(AnomalyDetectionService.class);

    private static final AttributeKey<ClientSession> SESSION_KEY = AttributeKey.valueOf("session");

    private static final int MAX_PROFILES = 10_000;

    private final ServerProperties serverProperties;
    private final DiscordWebhookService discordWebhook;
    private final ConnectionPoolService connectionPool;
    private final BlacklistService blacklistService;
    private final ConcurrentHashMap<String, ThreatProfile> profiles = new ConcurrentHashMap<>();

    public int recordViolation(String ip, ViolationType type) {
        if (profiles.size() >= MAX_PROFILES && !profiles.containsKey(ip)) {
            evictStaleProfiles();
        }
        ThreatProfile profile = profiles.computeIfAbsent(ip, k -> new ThreatProfile());
        profile.addViolation(type);

        int windowSeconds = serverProperties.getAnomalyDetection().getWindowSeconds();
        int score = profile.computeScore(windowSeconds);
        int threshold = serverProperties.getAnomalyDetection().getBlockThreshold();

        Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(windowSeconds);
        if (!patterns.isEmpty()) {
            log.warn("SUSPICIOUS PATTERNS from {} - {} - score: {}/{}, violation: {}",
                    ip, patterns, score, threshold, type);
        }

        if (score >= threshold) {
            log.error("BLOCKED IP {} - threat score {}/{} - violation: {} - patterns: {}",
                    ip, score, threshold, type, patterns);

            autoBlacklistUserForIp(ip, score);
            int disconnected = connectionPool.disconnectIp(ip);
            log.info("Disconnected {} active connections from blocked IP {}", disconnected, ip);

            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("IP", ip);
            fields.put("Score", score + "/" + threshold);
            fields.put("Violation", type.name());
            fields.put("Disconnected", String.valueOf(disconnected));
            if (!patterns.isEmpty()) fields.put("Patterns", patterns.toString());
            discordWebhook.sendAnomaly("\uD83D\uDED1 IP BLOCKED", "Threat score exceeded threshold",
                    DiscordWebhookService.COLOR_RED, fields);
        } else if (score > threshold / 2) {
            log.warn("Elevated threat from {} - score {}/{} - violation: {} - patterns: {}",
                    ip, score, threshold, type, patterns);
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("IP", ip);
            fields.put("Score", score + "/" + threshold);
            fields.put("Violation", type.name());
            if (!patterns.isEmpty()) fields.put("Patterns", patterns.toString());
            discordWebhook.sendAnomaly("\u26A0\uFE0F Elevated Threat", "Suspicious activity detected",
                    DiscordWebhookService.COLOR_ORANGE, fields);
        } else {
            log.info("Violation recorded for {} - type: {}, score: {}/{}", ip, type, score, threshold);
        }

        return score;
    }

    public boolean isBlocked(String ip) {
        ThreatProfile profile = profiles.get(ip);
        if (profile != null) {
            int windowSeconds = serverProperties.getAnomalyDetection().getWindowSeconds();
            int threshold = serverProperties.getAnomalyDetection().getBlockThreshold();
            return profile.computeScore(windowSeconds) >= threshold;
        }

        return false;
    }

    public int getThreatScore(String ip) {
        ThreatProfile profile = profiles.get(ip);
        if (profile == null) {
            return 0;
        }
        return profile.computeScore(serverProperties.getAnomalyDetection().getWindowSeconds());
    }

    public Set<ThreatProfile.SuspiciousPattern> getActivePatterns(String ip) {
        ThreatProfile profile = profiles.get(ip);
        if (profile == null) {
            return Set.of();
        }
        return profile.detectPatterns(serverProperties.getAnomalyDetection().getWindowSeconds());
    }

    private void autoBlacklistUserForIp(String ip, int score) {
        Set<Channel> channels = connectionPool.getChannelsForIp(ip);
        if (channels == null) return;

        for (Channel channel : channels) {
            ClientSession session = channel.attr(SESSION_KEY).get();
            if (session != null && session.getUser() != null) {
                User user = session.getUser();
                if (!blacklistService.isBlacklisted(user)) {
                    int autoBlockHours = serverProperties.getBlacklist().getAutoBlockHours();
                    blacklistService.blacklist(user,
                            "Auto-blocked: threat score " + score + " from IP " + ip,
                            Duration.ofHours(autoBlockHours),
                            "system");
                    log.warn("Auto-blacklisted user {} — threat score {} from IP {}", user.getUsername(), score, ip);
                }
            }
        }
    }

    @Scheduled(fixedRateString = "${server.anomaly-detection.status-interval-ms:300000}")
    public void logStatus() {
        int windowSeconds = serverProperties.getAnomalyDetection().getWindowSeconds();
        int threshold = serverProperties.getAnomalyDetection().getBlockThreshold();
        List<String> active = profiles.entrySet().stream()
                .map(e -> {
                    int score = e.getValue().computeScore(windowSeconds);
                    return score > 0 ? e.getKey() + "=" + score + "/" + threshold : null;
                })
                .filter(Objects::nonNull)
                .sorted()
                .toList();
        if (!active.isEmpty()) {
            log.info("[ANOMALY STATUS] {} active threat profile(s): {}", active.size(), active);
        }
    }

    @Scheduled(fixedRateString = "${server.anomaly-detection.cleanup-interval-ms:60000}")
    public void cleanup() {
        int windowSeconds = serverProperties.getAnomalyDetection().getWindowSeconds();
        int removed = 0;
        for (var entry : profiles.entrySet()) {
            entry.getValue().purgeExpired(windowSeconds);
            if (entry.getValue().isEmpty() || entry.getValue().isStale(windowSeconds * 2L)) {
                profiles.remove(entry.getKey());
                removed++;
            }
        }

        if (removed > 0) {
            log.debug("Anomaly detection cleanup: removed {} profiles ({} remaining)", removed, profiles.size());
        }
    }

    private void evictStaleProfiles() {
        int windowSeconds = serverProperties.getAnomalyDetection().getWindowSeconds();
        for (var entry : profiles.entrySet()) {
            if (entry.getValue().isStale(windowSeconds)) {
                profiles.remove(entry.getKey());
            }
        }
    }
}
