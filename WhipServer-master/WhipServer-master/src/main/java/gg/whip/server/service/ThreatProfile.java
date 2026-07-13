package gg.whip.server.service;

import lombok.Getter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class ThreatProfile {

    private static final int BURST_WINDOW_SECONDS = 10;
    private static final int BURST_THRESHOLD = 5;
    private static final double BURST_MULTIPLIER = 2.0;

    private static final int MULTI_VECTOR_THRESHOLD = 3;
    private static final double MULTI_VECTOR_MULTIPLIER = 1.5;

    private static final Set<ViolationType> CRYPTO_ATTACK_TYPES = EnumSet.of(
            ViolationType.HMAC_FAILED,
            ViolationType.DECRYPTION_FAILED,
            ViolationType.NONCE_REPLAY,
            ViolationType.CHALLENGE_FAILED
    );

    private static final Set<ViolationType> AUTH_ATTACK_TYPES = EnumSet.of(
            ViolationType.AUTH_FAILED,
            ViolationType.INVALID_TOKEN,
            ViolationType.HWID_MISMATCH,
            ViolationType.IP_MISMATCH
    );

    private final List<Violation> violations = new ArrayList<>();
    @Getter
    private volatile Instant lastActivity = Instant.now();

    public synchronized void addViolation(ViolationType type) {
        violations.add(new Violation(type, Instant.now()));
        lastActivity = Instant.now();
    }

    public synchronized int computeScore(long windowSeconds) {
        Instant cutoff = Instant.now().minusSeconds(windowSeconds);
        List<Violation> active = violations.stream()
                .filter(v -> v.timestamp().isAfter(cutoff))
                .toList();

        if (active.isEmpty()) {
            return 0;
        }

        int baseScore = active.stream()
                .mapToInt(v -> v.type().getWeight())
                .sum();

        double multiplier = 1.0;

        if (detectBurst(active)) {
            multiplier *= BURST_MULTIPLIER;
        }

        if (detectMultiVector(active)) {
            multiplier *= MULTI_VECTOR_MULTIPLIER;
        }

        if (detectEscalation(active)) {
            multiplier *= 1.75;
        }

        return (int) (baseScore * multiplier);
    }

    private boolean detectBurst(List<Violation> active) {
        if (active.size() < BURST_THRESHOLD) {
            return false;
        }
        Instant burstCutoff = Instant.now().minusSeconds(BURST_WINDOW_SECONDS);
        long recentCount = active.stream()
                .filter(v -> v.timestamp().isAfter(burstCutoff))
                .count();
        return recentCount >= BURST_THRESHOLD;
    }

    private boolean detectMultiVector(List<Violation> active) {
        Set<ViolationType> distinctTypes = active.stream()
                .map(Violation::type)
                .collect(Collectors.toSet());
        return distinctTypes.size() >= MULTI_VECTOR_THRESHOLD;
    }

    private boolean detectEscalation(List<Violation> active) {
        int firstCryptoIndex = -1;
        int lastAuthIndex = -1;

        for (int i = 0; i < active.size(); i++) {
            ViolationType type = active.get(i).type();
            if (CRYPTO_ATTACK_TYPES.contains(type) && firstCryptoIndex == -1) {
                firstCryptoIndex = i;
            }
            if (AUTH_ATTACK_TYPES.contains(type)) {
                lastAuthIndex = i;
            }
        }

        return firstCryptoIndex >= 0 && lastAuthIndex >= 0 && firstCryptoIndex < lastAuthIndex;
    }

    public synchronized Set<SuspiciousPattern> detectPatterns(long windowSeconds) {
        Instant cutoff = Instant.now().minusSeconds(windowSeconds);
        List<Violation> active = violations.stream()
                .filter(v -> v.timestamp().isAfter(cutoff))
                .toList();

        Set<SuspiciousPattern> patterns = EnumSet.noneOf(SuspiciousPattern.class);
        if (detectBurst(active)) patterns.add(SuspiciousPattern.BURST);
        if (detectMultiVector(active)) patterns.add(SuspiciousPattern.MULTI_VECTOR);
        if (detectEscalation(active)) patterns.add(SuspiciousPattern.ESCALATION);

        long replayCount = active.stream()
                .filter(v -> v.type() == ViolationType.NONCE_REPLAY || v.type() == ViolationType.REQUEST_REPLAY)
                .count();
        if (replayCount >= 3) patterns.add(SuspiciousPattern.RAPID_REPLAY);

        return patterns;
    }

    public synchronized void purgeExpired(long windowSeconds) {
        Instant cutoff = Instant.now().minusSeconds(windowSeconds);
        violations.removeIf(v -> !v.timestamp().isAfter(cutoff));
    }

    public synchronized boolean isEmpty() {
        return violations.isEmpty();
    }

    public boolean isStale(long maxIdleSeconds) {
        return Instant.now().minusSeconds(maxIdleSeconds).isAfter(lastActivity);
    }

    public record Violation(ViolationType type, Instant timestamp) {}

    public enum SuspiciousPattern {
        BURST,
        MULTI_VECTOR,
        ESCALATION,
        RAPID_REPLAY
    }
}
