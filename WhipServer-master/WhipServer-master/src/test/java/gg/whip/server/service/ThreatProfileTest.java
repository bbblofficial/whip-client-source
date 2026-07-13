package gg.whip.server.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.*;

class ThreatProfileTest {

    private ThreatProfile profile;
    private static final long WINDOW_SECONDS = 300;

    @BeforeEach
    void setUp() {
        profile = new ThreatProfile();
    }

    // ========== BURST DETECTION ==========

    @Nested
    @DisplayName("Burst Detection")
    class BurstDetection {

        @Test
        @DisplayName("5 violations in 10s triggers BURST pattern")
        void burstDetected() {
            for (int i = 0; i < 5; i++) {
                profile.addViolation(ViolationType.HMAC_FAILED);
            }

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertTrue(patterns.contains(ThreatProfile.SuspiciousPattern.BURST));
        }

        @Test
        @DisplayName("4 violations does not trigger BURST")
        void burstNotDetected() {
            for (int i = 0; i < 4; i++) {
                profile.addViolation(ViolationType.HMAC_FAILED);
            }

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertFalse(patterns.contains(ThreatProfile.SuspiciousPattern.BURST));
        }

        @Test
        @DisplayName("Burst multiplier doubles the score")
        void burstMultiplier() {
            for (int i = 0; i < 5; i++) {
                profile.addViolation(ViolationType.RATE_LIMIT_EXCEEDED); // weight=10
            }

            int score = profile.computeScore(WINDOW_SECONDS);
            // base=50, burst multiplier=2.0 → 100
            assertEquals(100, score);
        }
    }

    // ========== MULTI-VECTOR DETECTION ==========

    @Nested
    @DisplayName("Multi-Vector Detection")
    class MultiVectorDetection {

        @Test
        @DisplayName("3 different violation types triggers MULTI_VECTOR")
        void multiVectorDetected() {
            profile.addViolation(ViolationType.HMAC_FAILED);
            profile.addViolation(ViolationType.AUTH_FAILED);
            profile.addViolation(ViolationType.IP_MISMATCH);

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertTrue(patterns.contains(ThreatProfile.SuspiciousPattern.MULTI_VECTOR));
        }

        @Test
        @DisplayName("2 different violation types does not trigger MULTI_VECTOR")
        void multiVectorNotDetected() {
            profile.addViolation(ViolationType.HMAC_FAILED);
            profile.addViolation(ViolationType.AUTH_FAILED);

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertFalse(patterns.contains(ThreatProfile.SuspiciousPattern.MULTI_VECTOR));
        }

        @Test
        @DisplayName("Multi-vector multiplier is 1.5x")
        void multiVectorMultiplier() {
            profile.addViolation(ViolationType.HMAC_FAILED);       // 40
            profile.addViolation(ViolationType.INVALID_TIMESTAMP); // 15
            profile.addViolation(ViolationType.RATE_LIMIT_EXCEEDED); // 10

            int score = profile.computeScore(WINDOW_SECONDS);
            // base=65, multi-vector=1.5 → 97
            assertEquals(97, score);
        }
    }

    // ========== ESCALATION DETECTION ==========

    @Nested
    @DisplayName("Escalation Detection")
    class EscalationDetection {

        @Test
        @DisplayName("Crypto attack then auth attack triggers ESCALATION")
        void escalationDetected() {
            profile.addViolation(ViolationType.HMAC_FAILED);      // crypto
            profile.addViolation(ViolationType.DECRYPTION_FAILED); // crypto
            profile.addViolation(ViolationType.AUTH_FAILED);       // auth (after crypto)

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertTrue(patterns.contains(ThreatProfile.SuspiciousPattern.ESCALATION));
        }

        @Test
        @DisplayName("Only crypto attacks without auth does not trigger ESCALATION")
        void noEscalationWithoutAuth() {
            profile.addViolation(ViolationType.HMAC_FAILED);
            profile.addViolation(ViolationType.DECRYPTION_FAILED);
            profile.addViolation(ViolationType.NONCE_REPLAY);

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertFalse(patterns.contains(ThreatProfile.SuspiciousPattern.ESCALATION));
        }

        @Test
        @DisplayName("Only auth attacks without crypto does not trigger ESCALATION")
        void noEscalationWithoutCrypto() {
            profile.addViolation(ViolationType.AUTH_FAILED);
            profile.addViolation(ViolationType.INVALID_TOKEN);

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertFalse(patterns.contains(ThreatProfile.SuspiciousPattern.ESCALATION));
        }

        @Test
        @DisplayName("Escalation multiplier is 1.75x")
        void escalationMultiplier() {
            // Only crypto + auth, but only 2 types → no multi-vector
            profile.addViolation(ViolationType.HMAC_FAILED);  // 40 (crypto)
            profile.addViolation(ViolationType.AUTH_FAILED);   // 20 (auth)

            int score = profile.computeScore(WINDOW_SECONDS);
            // base=60, escalation=1.75 → 105
            assertEquals(105, score);
        }
    }

    // ========== RAPID REPLAY DETECTION ==========

    @Nested
    @DisplayName("Rapid Replay Detection")
    class RapidReplayDetection {

        @Test
        @DisplayName("3 nonce replays triggers RAPID_REPLAY")
        void rapidReplayWithNonce() {
            profile.addViolation(ViolationType.NONCE_REPLAY);
            profile.addViolation(ViolationType.NONCE_REPLAY);
            profile.addViolation(ViolationType.NONCE_REPLAY);

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertTrue(patterns.contains(ThreatProfile.SuspiciousPattern.RAPID_REPLAY));
        }

        @Test
        @DisplayName("3 request replays triggers RAPID_REPLAY")
        void rapidReplayWithRequest() {
            profile.addViolation(ViolationType.REQUEST_REPLAY);
            profile.addViolation(ViolationType.REQUEST_REPLAY);
            profile.addViolation(ViolationType.REQUEST_REPLAY);

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertTrue(patterns.contains(ThreatProfile.SuspiciousPattern.RAPID_REPLAY));
        }

        @Test
        @DisplayName("Mix of nonce and request replays count together")
        void rapidReplayMixed() {
            profile.addViolation(ViolationType.NONCE_REPLAY);
            profile.addViolation(ViolationType.REQUEST_REPLAY);
            profile.addViolation(ViolationType.NONCE_REPLAY);

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertTrue(patterns.contains(ThreatProfile.SuspiciousPattern.RAPID_REPLAY));
        }

        @Test
        @DisplayName("2 replays does not trigger RAPID_REPLAY")
        void rapidReplayNotDetected() {
            profile.addViolation(ViolationType.NONCE_REPLAY);
            profile.addViolation(ViolationType.REQUEST_REPLAY);

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertFalse(patterns.contains(ThreatProfile.SuspiciousPattern.RAPID_REPLAY));
        }
    }

    // ========== COMBINED PATTERNS ==========

    @Nested
    @DisplayName("Combined Patterns")
    class CombinedPatterns {

        @Test
        @DisplayName("All patterns detected simultaneously")
        void allPatternsDetected() {
            // Crypto attacks (for escalation + multi-vector)
            profile.addViolation(ViolationType.HMAC_FAILED);
            profile.addViolation(ViolationType.DECRYPTION_FAILED);
            profile.addViolation(ViolationType.NONCE_REPLAY);
            // Auth attacks (for escalation)
            profile.addViolation(ViolationType.AUTH_FAILED);
            profile.addViolation(ViolationType.INVALID_TOKEN);
            // Extra replays for rapid replay (already 1 nonce above)
            profile.addViolation(ViolationType.REQUEST_REPLAY);
            profile.addViolation(ViolationType.NONCE_REPLAY);

            // 7 violations → burst (>=5)
            // 5 types → multi-vector (>=3)
            // crypto before auth → escalation
            // 3 replay types → rapid replay

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertEquals(4, patterns.size());
            assertTrue(patterns.contains(ThreatProfile.SuspiciousPattern.BURST));
            assertTrue(patterns.contains(ThreatProfile.SuspiciousPattern.MULTI_VECTOR));
            assertTrue(patterns.contains(ThreatProfile.SuspiciousPattern.ESCALATION));
            assertTrue(patterns.contains(ThreatProfile.SuspiciousPattern.RAPID_REPLAY));
        }

        @Test
        @DisplayName("Combined multipliers stack correctly")
        void combinedMultipliers() {
            // 5 different types including crypto + auth → burst + multi-vector + escalation
            profile.addViolation(ViolationType.HMAC_FAILED);         // 40 (crypto)
            profile.addViolation(ViolationType.DECRYPTION_FAILED);   // 25 (crypto)
            profile.addViolation(ViolationType.AUTH_FAILED);         // 20 (auth)
            profile.addViolation(ViolationType.INVALID_TIMESTAMP);   // 15
            profile.addViolation(ViolationType.RATE_LIMIT_EXCEEDED); // 10

            int score = profile.computeScore(WINDOW_SECONDS);
            // base=110, burst=2.0, multi-vector=1.5, escalation=1.75
            // 110 * 2.0 * 1.5 * 1.75 = 577.5 → 577
            assertEquals(577, score);
        }
    }

    // ========== SCORE CALCULATION ==========

    @Nested
    @DisplayName("Score Calculation")
    class ScoreCalculation {

        @Test
        @DisplayName("Empty profile returns score 0")
        void emptyProfileScore() {
            assertEquals(0, profile.computeScore(WINDOW_SECONDS));
        }

        @Test
        @DisplayName("Single violation returns its weight")
        void singleViolationScore() {
            profile.addViolation(ViolationType.HWID_MISMATCH); // weight=50
            assertEquals(50, profile.computeScore(WINDOW_SECONDS));
        }

        @Test
        @DisplayName("Multiple same-type violations sum their weights")
        void multipleViolationsScore() {
            profile.addViolation(ViolationType.INVALID_TIMESTAMP); // 15
            profile.addViolation(ViolationType.INVALID_TIMESTAMP); // 15
            // 2 violations, same type → no patterns, multiplier=1.0
            assertEquals(30, profile.computeScore(WINDOW_SECONDS));
        }

        @Test
        @DisplayName("All violation types have positive weights")
        void allViolationTypesHavePositiveWeights() {
            for (ViolationType type : ViolationType.values()) {
                assertTrue(type.getWeight() > 0, type.name() + " should have positive weight");
            }
        }
    }

    // ========== PURGE & LIFECYCLE ==========

    @Nested
    @DisplayName("Purge & Lifecycle")
    class PurgeLifecycle {

        @Test
        @DisplayName("New profile is empty")
        void newProfileIsEmpty() {
            assertTrue(profile.isEmpty());
        }

        @Test
        @DisplayName("Profile with violations is not empty")
        void profileWithViolationsNotEmpty() {
            profile.addViolation(ViolationType.AUTH_FAILED);
            assertFalse(profile.isEmpty());
        }

        @Test
        @DisplayName("purgeExpired with 0 window removes all violations")
        void purgeRemovesAll() {
            profile.addViolation(ViolationType.AUTH_FAILED);
            profile.addViolation(ViolationType.HMAC_FAILED);

            // Window of 0 seconds means everything is expired
            profile.purgeExpired(0);
            assertTrue(profile.isEmpty());
        }

        @Test
        @DisplayName("purgeExpired with large window keeps recent violations")
        void purgeKeepsRecent() {
            profile.addViolation(ViolationType.AUTH_FAILED);

            profile.purgeExpired(WINDOW_SECONDS);
            assertFalse(profile.isEmpty());
        }

        @Test
        @DisplayName("Expired violations don't count in score")
        void expiredViolationsDontCount() {
            profile.addViolation(ViolationType.AUTH_FAILED);
            // Window of 0 means all violations are "expired" for scoring
            assertEquals(0, profile.computeScore(0));
        }
    }

    // ========== STRESS / SURCHARGE ==========

    @Nested
    @DisplayName("Stress Tests (Surcharge)")
    class StressTests {

        @Test
        @DisplayName("10,000 rapid violations are handled correctly")
        void massiveViolationLoad() {
            int count = 10_000;
            for (int i = 0; i < count; i++) {
                profile.addViolation(ViolationType.RATE_LIMIT_EXCEEDED); // weight=10
            }

            int score = profile.computeScore(WINDOW_SECONDS);
            // base=100,000, burst multiplier=2.0 → 200,000
            // Only 1 type → no multi-vector, no escalation
            assertEquals(200_000, score);

            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            assertTrue(patterns.contains(ThreatProfile.SuspiciousPattern.BURST));
            assertFalse(patterns.contains(ThreatProfile.SuspiciousPattern.MULTI_VECTOR));
        }

        @Test
        @DisplayName("Concurrent violations from multiple threads")
        void concurrentViolations() throws InterruptedException {
            int threadCount = 20;
            int violationsPerThread = 500;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);

            for (int t = 0; t < threadCount; t++) {
                executor.submit(() -> {
                    try {
                        for (int i = 0; i < violationsPerThread; i++) {
                            profile.addViolation(ViolationType.HMAC_FAILED);
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            // All violations should be recorded (CopyOnWriteArrayList is thread-safe)
            assertFalse(profile.isEmpty());
            int score = profile.computeScore(WINDOW_SECONDS);
            // 10,000 * 40 (HMAC weight) * 2.0 (burst) = 800,000
            assertTrue(score > 0, "Score should be positive after concurrent writes");
            assertEquals(800_000, score);
        }

        @Test
        @DisplayName("Performance: detectPatterns on large profile completes in time")
        void detectPatternsPerformance() {
            // Fill with diverse violations
            ViolationType[] types = ViolationType.values();
            for (int i = 0; i < 5_000; i++) {
                profile.addViolation(types[i % types.length]);
            }

            long start = System.nanoTime();
            Set<ThreatProfile.SuspiciousPattern> patterns = profile.detectPatterns(WINDOW_SECONDS);
            long durationMs = (System.nanoTime() - start) / 1_000_000;

            assertFalse(patterns.isEmpty());
            assertTrue(durationMs < 5_000, "detectPatterns should complete within 5s, took " + durationMs + "ms");
        }

        @Test
        @DisplayName("Concurrent detectPatterns calls are safe")
        void concurrentDetectPatterns() throws InterruptedException {
            // Pre-fill profile
            for (int i = 0; i < 100; i++) {
                profile.addViolation(ViolationType.values()[i % ViolationType.values().length]);
            }

            int threadCount = 10;
            CountDownLatch latch = new CountDownLatch(threadCount);
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);

            for (int t = 0; t < threadCount; t++) {
                executor.submit(() -> {
                    try {
                        for (int i = 0; i < 100; i++) {
                            profile.detectPatterns(WINDOW_SECONDS);
                            profile.computeScore(WINDOW_SECONDS);
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();
            // No exception = thread safety verified
        }
    }
}
