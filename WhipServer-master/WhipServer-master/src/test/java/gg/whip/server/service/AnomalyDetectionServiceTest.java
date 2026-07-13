package gg.whip.server.service;

import gg.whip.server.config.ServerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class AnomalyDetectionServiceTest {

    @Mock
    private DiscordWebhookService discordWebhook;

    @Mock
    private ConnectionPoolService connectionPool;

    @Mock
    private BlacklistService blacklistService;

    private ServerProperties serverProperties;
    private AnomalyDetectionService service;

    @BeforeEach
    void setUp() {
        serverProperties = new ServerProperties();
        serverProperties.getAnomalyDetection().setBlockThreshold(100);
        serverProperties.getAnomalyDetection().setWindowSeconds(300);

        // Configure mocks with lenient() to avoid UnnecessaryStubbingException
        lenient().when(connectionPool.disconnectIp(anyString())).thenReturn(0);

        service = new AnomalyDetectionService(serverProperties, discordWebhook, connectionPool, blacklistService);
    }

    // ========== RECORD VIOLATION ==========

    @Nested
    @DisplayName("Record Violation")
    class RecordViolation {

        @Test
        @DisplayName("Returns score after recording violation")
        void returnsScore() {
            int score = service.recordViolation("192.168.1.1", ViolationType.AUTH_FAILED);
            assertTrue(score > 0);
        }

        @Test
        @DisplayName("Score accumulates with multiple violations")
        void scoreAccumulates() {
            service.recordViolation("192.168.1.1", ViolationType.AUTH_FAILED); // 20
            int score = service.recordViolation("192.168.1.1", ViolationType.AUTH_FAILED); // 20
            assertEquals(40, score); // 2 same type, no patterns
        }

        @Test
        @DisplayName("Different IPs have separate profiles")
        void separateProfiles() {
            service.recordViolation("10.0.0.1", ViolationType.HWID_MISMATCH); // 50
            service.recordViolation("10.0.0.2", ViolationType.RATE_LIMIT_EXCEEDED); // 10

            assertEquals(50, service.getThreatScore("10.0.0.1"));
            assertEquals(10, service.getThreatScore("10.0.0.2"));
        }
    }

    // ========== IS BLOCKED ==========

    @Nested
    @DisplayName("IP Blocking")
    class IpBlocking {

        @Test
        @DisplayName("Unknown IP is not blocked")
        void unknownIpNotBlocked() {
            assertFalse(service.isBlocked("1.2.3.4"));
        }

        @Test
        @DisplayName("IP is blocked when score reaches threshold")
        void blockedAtThreshold() {
            // HWID_MISMATCH=50 * 2 = 100 base, but same type so no multi-vector
            // Need to reach 100. Let's use HMAC_FAILED(40) + DECRYPTION_FAILED(25) + AUTH_FAILED(20) = 85
            // 3 types → multi-vector 1.5x + escalation 1.75x (crypto+auth)
            // 85 * 1.5 * 1.75 = 223 → blocked
            service.recordViolation("10.0.0.1", ViolationType.HMAC_FAILED);
            service.recordViolation("10.0.0.1", ViolationType.DECRYPTION_FAILED);
            service.recordViolation("10.0.0.1", ViolationType.AUTH_FAILED);

            assertTrue(service.isBlocked("10.0.0.1"));
        }

        @Test
        @DisplayName("IP is not blocked when score is below threshold")
        void notBlockedBelowThreshold() {
            service.recordViolation("10.0.0.1", ViolationType.RATE_LIMIT_EXCEEDED); // 10
            assertFalse(service.isBlocked("10.0.0.1"));
        }
    }

    // ========== THREAT SCORE ==========

    @Nested
    @DisplayName("Threat Score")
    class ThreatScore {

        @Test
        @DisplayName("Unknown IP returns 0")
        void unknownIpReturnsZero() {
            assertEquals(0, service.getThreatScore("unknown"));
        }

        @Test
        @DisplayName("Returns correct score for known IP")
        void correctScore() {
            service.recordViolation("10.0.0.1", ViolationType.HWID_MISMATCH); // 50
            assertEquals(50, service.getThreatScore("10.0.0.1"));
        }
    }

    // ========== ACTIVE PATTERNS ==========

    @Nested
    @DisplayName("Active Patterns")
    class ActivePatterns {

        @Test
        @DisplayName("Unknown IP returns empty patterns")
        void unknownIpEmptyPatterns() {
            assertTrue(service.getActivePatterns("unknown").isEmpty());
        }

        @Test
        @DisplayName("Returns correct patterns for IP with burst")
        void detectsBurst() {
            for (int i = 0; i < 5; i++) {
                service.recordViolation("10.0.0.1", ViolationType.AUTH_FAILED);
            }

            Set<ThreatProfile.SuspiciousPattern> patterns = service.getActivePatterns("10.0.0.1");
            assertTrue(patterns.contains(ThreatProfile.SuspiciousPattern.BURST));
        }
    }

    // ========== DISCORD ALERTS ==========

    @Nested
    @DisplayName("Discord Alerts")
    class DiscordAlerts {

        @Test
        @DisplayName("Discord alert sent when IP is blocked (score >= threshold)")
        void alertOnBlock() {
            // Reach score >= 100 quickly
            service.recordViolation("10.0.0.1", ViolationType.HMAC_FAILED);      // crypto
            service.recordViolation("10.0.0.1", ViolationType.DECRYPTION_FAILED); // crypto
            service.recordViolation("10.0.0.1", ViolationType.AUTH_FAILED);       // auth → escalation

            verify(discordWebhook, atLeastOnce()).sendAnomaly(
                    contains("BLOCKED"), anyString(), eq(DiscordWebhookService.COLOR_RED), anyMap());
        }

        @Test
        @DisplayName("Discord warning sent when score > threshold/2")
        void warningOnElevatedThreat() {
            // HWID_MISMATCH = 50, threshold/2 = 50, need > 50
            service.recordViolation("10.0.0.1", ViolationType.HWID_MISMATCH); // 50
            service.recordViolation("10.0.0.1", ViolationType.RATE_LIMIT_EXCEEDED); // +10 = 60

            verify(discordWebhook, atLeastOnce()).sendAnomaly(
                    contains("Elevated"), anyString(), eq(DiscordWebhookService.COLOR_ORANGE), anyMap());
        }

        @Test
        @DisplayName("No Discord alert when score is low")
        void noAlertOnLowScore() {
            service.recordViolation("10.0.0.1", ViolationType.RATE_LIMIT_EXCEEDED); // 10

            verify(discordWebhook, never()).sendAnomaly(anyString(), anyString(), anyInt(), anyMap());
        }
    }

    // ========== CLEANUP ==========

    @Nested
    @DisplayName("Cleanup")
    class Cleanup {

        @Test
        @DisplayName("Cleanup removes empty profiles")
        void cleanupRemovesEmptyProfiles() {
            // Set window to 0 so everything is instantly expired
            serverProperties.getAnomalyDetection().setWindowSeconds(0);
            service.recordViolation("10.0.0.1", ViolationType.RATE_LIMIT_EXCEEDED);

            service.cleanup();

            assertEquals(0, service.getThreatScore("10.0.0.1"));
        }

        @Test
        @DisplayName("Cleanup keeps active profiles")
        void cleanupKeepsActiveProfiles() {
            service.recordViolation("10.0.0.1", ViolationType.AUTH_FAILED);

            service.cleanup();

            assertTrue(service.getThreatScore("10.0.0.1") > 0);
        }
    }

    // ========== STRESS / SURCHARGE ==========

    @Nested
    @DisplayName("Stress Tests (Surcharge)")
    class StressTests {

        @Test
        @DisplayName("50 distinct IPs with 100 violations each")
        void massiveIpLoad() {
            for (int ip = 0; ip < 50; ip++) {
                String ipAddr = "10.0.0." + ip;
                for (int v = 0; v < 100; v++) {
                    service.recordViolation(ipAddr, ViolationType.RATE_LIMIT_EXCEEDED);
                }
            }

            // All 50 IPs should have scores
            for (int ip = 0; ip < 50; ip++) {
                String ipAddr = "10.0.0." + ip;
                assertTrue(service.getThreatScore(ipAddr) > 0,
                        "IP " + ipAddr + " should have a positive score");
            }

            // All should be blocked (100 * 10 = 1000 base * 2.0 burst = 2000 >> 100 threshold)
            for (int ip = 0; ip < 50; ip++) {
                assertTrue(service.isBlocked("10.0.0." + ip));
            }
        }

        @Test
        @DisplayName("Concurrent violations from 20 threads on same IP")
        void concurrentViolationsSameIp() throws InterruptedException {
            int threadCount = 20;
            int violationsPerThread = 50;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);

            for (int t = 0; t < threadCount; t++) {
                executor.submit(() -> {
                    try {
                        for (int i = 0; i < violationsPerThread; i++) {
                            service.recordViolation("10.0.0.1", ViolationType.AUTH_FAILED);
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            assertTrue(service.isBlocked("10.0.0.1"));
            assertTrue(service.getThreatScore("10.0.0.1") > 0);
        }

        @Test
        @DisplayName("Concurrent violations from 20 threads on different IPs")
        void concurrentViolationsDifferentIps() throws InterruptedException {
            int threadCount = 20;
            int violationsPerThread = 100;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger errors = new AtomicInteger(0);

            for (int t = 0; t < threadCount; t++) {
                final int threadId = t;
                executor.submit(() -> {
                    try {
                        String ip = "10.0." + threadId + ".1";
                        for (int i = 0; i < violationsPerThread; i++) {
                            service.recordViolation(ip, ViolationType.HMAC_FAILED);
                        }
                    } catch (Exception e) {
                        errors.incrementAndGet();
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            assertEquals(0, errors.get(), "No errors should occur during concurrent access");

            // All 20 IPs should be blocked
            for (int t = 0; t < threadCount; t++) {
                String ip = "10.0." + t + ".1";
                assertTrue(service.isBlocked(ip), ip + " should be blocked");
            }
        }

        @Test
        @DisplayName("Concurrent reads and writes are safe")
        void concurrentReadsAndWrites() throws InterruptedException {
            int threadCount = 10;
            CountDownLatch latch = new CountDownLatch(threadCount * 2);
            ExecutorService executor = Executors.newFixedThreadPool(threadCount * 2);
            AtomicInteger errors = new AtomicInteger(0);

            // Writer threads
            for (int t = 0; t < threadCount; t++) {
                executor.submit(() -> {
                    try {
                        for (int i = 0; i < 200; i++) {
                            service.recordViolation("10.0.0.1", ViolationType.AUTH_FAILED);
                        }
                    } catch (Exception e) {
                        errors.incrementAndGet();
                    } finally {
                        latch.countDown();
                    }
                });
            }

            // Reader threads
            for (int t = 0; t < threadCount; t++) {
                executor.submit(() -> {
                    try {
                        for (int i = 0; i < 200; i++) {
                            service.isBlocked("10.0.0.1");
                            service.getThreatScore("10.0.0.1");
                            service.getActivePatterns("10.0.0.1");
                        }
                    } catch (Exception e) {
                        errors.incrementAndGet();
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            assertEquals(0, errors.get(), "No errors during concurrent read/write operations");
        }
    }
}
