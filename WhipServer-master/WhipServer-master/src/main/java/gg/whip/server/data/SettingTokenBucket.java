package gg.whip.server.data;

/**
 * Token bucket for the remote-blessed settings mass-toggle defence.
 *
 * Per-(session, settingKey) instance. State is in-memory only — when the
 * session disconnects everything is GC'd. No DB.
 *
 * Defaults match WhipLoader/REMOTE_CONFIG_DESIGN.md:
 *   - capacity: 10 burst tokens
 *   - refill:   1 token every 120 seconds
 *   - net cap:  ~30 mutations per hour per setting
 */
public final class SettingTokenBucket {

    public static final int    CAPACITY      = 10;
    public static final long   REFILL_PERIOD_MS = 120_000L;

    private double tokens;
    private long   lastRefillMs;

    public SettingTokenBucket() {
        this.tokens = CAPACITY;
        this.lastRefillMs = System.currentTimeMillis();
    }

    /**
     * Try to consume one token. Returns true if accepted, false if the
     * bucket is empty (rate-limited).
     */
    public synchronized boolean tryConsume() {
        refill();
        if (tokens >= 1.0) {
            tokens -= 1.0;
            return true;
        }
        return false;
    }

    /**
     * How many ms until at least one token will be available. Used to fill
     * the `expiresAt` field of a RATE_LIMITED response so the client can
     * gate its next request.
     */
    public synchronized long retryAfterMs() {
        refill();
        if (tokens >= 1.0) return 0L;
        double needed = 1.0 - tokens;
        return (long) Math.ceil(needed * REFILL_PERIOD_MS);
    }

    private void refill() {
        long now = System.currentTimeMillis();
        long elapsed = now - lastRefillMs;
        if (elapsed <= 0) return;
        double add = (double) elapsed / (double) REFILL_PERIOD_MS;
        if (add > 0) {
            tokens = Math.min(CAPACITY, tokens + add);
            lastRefillMs = now;
        }
    }
}
