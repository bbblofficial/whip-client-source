package gg.whip.server.handler.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class RateLimiterHandler {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterHandler.class);

    private static final int MAX_REQUESTS_PER_MINUTE = 60;
    private static final int MAX_AUTH_PER_MINUTE = 5;
    private static final long WINDOW_MS = 60_000;

    private final ConcurrentHashMap<String, RateLimitEntry> requestLimits = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RateLimitEntry> authLimits = new ConcurrentHashMap<>();

    public boolean isRequestAllowed(String ip) {
        return checkLimit(requestLimits, ip, MAX_REQUESTS_PER_MINUTE);
    }

    public boolean isAuthAllowed(String ip) {
        return checkLimit(authLimits, ip, MAX_AUTH_PER_MINUTE);
    }

    private boolean checkLimit(ConcurrentHashMap<String, RateLimitEntry> limits, String key, int maxRequests) {
        long now = System.currentTimeMillis();
        RateLimitEntry entry = limits.compute(key, (k, existing) -> {
            if (existing == null || now - existing.windowStart > WINDOW_MS) {
                return new RateLimitEntry(now, new AtomicInteger(1));
            }
            existing.count.incrementAndGet();
            return existing;
        });
        return entry.count.get() <= maxRequests;
    }

    @Scheduled(fixedRate = 120_000)
    public void cleanup() {
        long now = System.currentTimeMillis();
        int removed = 0;
        removed += evictExpired(requestLimits, now);
        removed += evictExpired(authLimits, now);
        if (removed > 0) {
            log.debug("Rate limiter cleanup: evicted {} expired entries", removed);
        }
    }

    private int evictExpired(ConcurrentHashMap<String, RateLimitEntry> limits, long now) {
        int count = 0;
        var it = limits.entrySet().iterator();
        while (it.hasNext()) {
            var entry = it.next();
            if (now - entry.getValue().windowStart > WINDOW_MS) {
                it.remove();
                count++;
            }
        }
        return count;
    }

    private record RateLimitEntry(long windowStart, AtomicInteger count) {}
}