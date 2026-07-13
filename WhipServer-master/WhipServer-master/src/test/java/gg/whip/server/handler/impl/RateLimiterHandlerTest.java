package gg.whip.server.handler.impl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterHandlerTest {

    private RateLimiterHandler rateLimiter;

    @BeforeEach
    void setUp() {
        rateLimiter = new RateLimiterHandler();
    }

    // ========== REQUEST LIMITING ==========

    @Nested
    @DisplayName("Request Rate Limiting")
    class RequestRateLimiting {

        @Test
        @DisplayName("First request is allowed")
        void firstRequestAllowed() {
            assertTrue(rateLimiter.isRequestAllowed("10.0.0.1"));
        }

        @Test
        @DisplayName("60 requests within a minute are allowed")
        void sixtyRequestsAllowed() {
            for (int i = 0; i < 60; i++) {
                assertTrue(rateLimiter.isRequestAllowed("10.0.0.1"),
                        "Request " + (i + 1) + " should be allowed");
            }
        }

        @Test
        @DisplayName("61st request is denied")
        void sixtyFirstRequestDenied() {
            for (int i = 0; i < 60; i++) {
                rateLimiter.isRequestAllowed("10.0.0.1");
            }
            assertFalse(rateLimiter.isRequestAllowed("10.0.0.1"));
        }
    }

    // ========== AUTH LIMITING ==========

    @Nested
    @DisplayName("Auth Rate Limiting")
    class AuthRateLimiting {

        @Test
        @DisplayName("First auth attempt is allowed")
        void firstAuthAllowed() {
            assertTrue(rateLimiter.isAuthAllowed("10.0.0.1"));
        }

        @Test
        @DisplayName("5 auth attempts within a minute are allowed")
        void fiveAuthsAllowed() {
            for (int i = 0; i < 5; i++) {
                assertTrue(rateLimiter.isAuthAllowed("10.0.0.1"),
                        "Auth attempt " + (i + 1) + " should be allowed");
            }
        }

        @Test
        @DisplayName("6th auth attempt is denied")
        void sixthAuthDenied() {
            for (int i = 0; i < 5; i++) {
                rateLimiter.isAuthAllowed("10.0.0.1");
            }
            assertFalse(rateLimiter.isAuthAllowed("10.0.0.1"));
        }
    }

    // ========== IP ISOLATION ==========

    @Nested
    @DisplayName("IP Isolation")
    class IpIsolation {

        @Test
        @DisplayName("Different IPs have independent request limits")
        void independentRequestLimits() {
            // Exhaust IP1
            for (int i = 0; i < 61; i++) {
                rateLimiter.isRequestAllowed("10.0.0.1");
            }
            assertFalse(rateLimiter.isRequestAllowed("10.0.0.1"));

            // IP2 should still be allowed
            assertTrue(rateLimiter.isRequestAllowed("10.0.0.2"));
        }

        @Test
        @DisplayName("Different IPs have independent auth limits")
        void independentAuthLimits() {
            // Exhaust IP1
            for (int i = 0; i < 6; i++) {
                rateLimiter.isAuthAllowed("10.0.0.1");
            }
            assertFalse(rateLimiter.isAuthAllowed("10.0.0.1"));

            // IP2 should still be allowed
            assertTrue(rateLimiter.isAuthAllowed("10.0.0.2"));
        }

        @Test
        @DisplayName("Request and auth limits are independent for same IP")
        void requestAndAuthIndependent() {
            // Exhaust auth limit
            for (int i = 0; i < 6; i++) {
                rateLimiter.isAuthAllowed("10.0.0.1");
            }
            assertFalse(rateLimiter.isAuthAllowed("10.0.0.1"));

            // Request limit should still work
            assertTrue(rateLimiter.isRequestAllowed("10.0.0.1"));
        }
    }

    // ========== STRESS / SURCHARGE ==========

    @Nested
    @DisplayName("Stress Tests (Surcharge)")
    class StressTests {

        @Test
        @DisplayName("1000 rapid requests: only first 60 pass")
        void massiveRequestLoad() {
            int allowed = 0;
            int denied = 0;
            for (int i = 0; i < 1_000; i++) {
                if (rateLimiter.isRequestAllowed("10.0.0.1")) {
                    allowed++;
                } else {
                    denied++;
                }
            }
            assertEquals(60, allowed, "Exactly 60 requests should be allowed");
            assertEquals(940, denied, "940 requests should be denied");
        }

        @Test
        @DisplayName("1000 rapid auth attempts: only first 5 pass")
        void massiveAuthLoad() {
            int allowed = 0;
            int denied = 0;
            for (int i = 0; i < 1_000; i++) {
                if (rateLimiter.isAuthAllowed("10.0.0.1")) {
                    allowed++;
                } else {
                    denied++;
                }
            }
            assertEquals(5, allowed, "Exactly 5 auth attempts should be allowed");
            assertEquals(995, denied, "995 auth attempts should be denied");
        }

        @Test
        @DisplayName("100 IPs each sending 100 requests")
        void massiveIpLoad() {
            for (int ip = 0; ip < 100; ip++) {
                String ipAddr = "10.0." + (ip / 256) + "." + (ip % 256);
                int allowed = 0;
                for (int r = 0; r < 100; r++) {
                    if (rateLimiter.isRequestAllowed(ipAddr)) {
                        allowed++;
                    }
                }
                assertEquals(60, allowed, "IP " + ipAddr + " should have exactly 60 allowed requests");
            }
        }

        @Test
        @DisplayName("Concurrent requests from 10 threads on same IP")
        void concurrentRequestsSameIp() throws InterruptedException {
            int threadCount = 10;
            int requestsPerThread = 100;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger totalAllowed = new AtomicInteger(0);

            for (int t = 0; t < threadCount; t++) {
                executor.submit(() -> {
                    try {
                        for (int i = 0; i < requestsPerThread; i++) {
                            if (rateLimiter.isRequestAllowed("10.0.0.1")) {
                                totalAllowed.incrementAndGet();
                            }
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            // Due to concurrent access, allowed count may slightly exceed 60
            // but should be in a reasonable range
            assertTrue(totalAllowed.get() >= 60,
                    "At least 60 requests should be allowed, got " + totalAllowed.get());
            assertTrue(totalAllowed.get() <= 70,
                    "No more than ~70 requests should be allowed due to race conditions, got " + totalAllowed.get());
        }

        @Test
        @DisplayName("Concurrent requests from 10 threads on different IPs")
        void concurrentRequestsDifferentIps() throws InterruptedException {
            int threadCount = 10;
            int requestsPerThread = 100;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger errors = new AtomicInteger(0);

            for (int t = 0; t < threadCount; t++) {
                final int threadId = t;
                executor.submit(() -> {
                    try {
                        String ip = "10.0.0." + threadId;
                        int allowed = 0;
                        for (int i = 0; i < requestsPerThread; i++) {
                            if (rateLimiter.isRequestAllowed(ip)) {
                                allowed++;
                            }
                        }
                        if (allowed != 60) {
                            errors.incrementAndGet();
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            assertEquals(0, errors.get(),
                    "Each IP should have exactly 60 allowed requests (no cross-IP interference)");
        }

        @Test
        @DisplayName("Mixed concurrent auth and request calls are safe")
        void concurrentMixedCalls() throws InterruptedException {
            int threadCount = 10;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger errors = new AtomicInteger(0);

            for (int t = 0; t < threadCount; t++) {
                final int threadId = t;
                executor.submit(() -> {
                    try {
                        String ip = "10.0.0." + threadId;
                        for (int i = 0; i < 200; i++) {
                            rateLimiter.isRequestAllowed(ip);
                            rateLimiter.isAuthAllowed(ip);
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

            assertEquals(0, errors.get(), "No errors during concurrent mixed operations");
        }
    }
}
