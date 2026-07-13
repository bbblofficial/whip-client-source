const ipCache = new Map<string, number[]>();

const MAX_ENTRIES = 10000;
let lastCleanup = Date.now();
const CLEANUP_INTERVAL = 60000; // 1 minute

function cleanup(windowMs: number) {
    const now = Date.now();
    if (now - lastCleanup < CLEANUP_INTERVAL) return;
    lastCleanup = now;

    for (const [ip, timestamps] of Array.from(ipCache.entries())) {
        const recent = timestamps.filter(t => now - t < windowMs);
        if (recent.length === 0) {
            ipCache.delete(ip);
        } else {
            ipCache.set(ip, recent);
        }
    }

    // Hard cap to prevent memory abuse
    if (ipCache.size > MAX_ENTRIES) {
        const entries = Array.from(ipCache.entries());
        entries.sort((a, b) => Math.max(...b[1]) - Math.max(...a[1]));
        ipCache.clear();
        for (const [ip, ts] of entries.slice(0, MAX_ENTRIES / 2)) {
            ipCache.set(ip, ts);
        }
    }
}

export function rateLimit(ip: string, limit: number = 5, windowMs: number = 60000) {
    cleanup(windowMs);

    const now = Date.now();
    const timestamps = ipCache.get(ip) || [];

    // Clean old timestamps
    const recentTimestamps = timestamps.filter(t => now - t < windowMs);

    if (recentTimestamps.length >= limit) {
        return false;
    }

    recentTimestamps.push(now);
    ipCache.set(ip, recentTimestamps);
    return true;
}
