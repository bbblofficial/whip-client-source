import crypto from "crypto";

const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret-change-in-production";

/** Session lifetime (seconds). 7 days — the 30 min limit logged admins out
 *  mid-session and made every server action fail with "Non autorisé". */
export const SESSION_MAX_AGE = 60 * 60 * 24 * 7;

export interface SessionPayload {
    userId: string;
    username: string;
    grade: string;
    iat: number; // issued at (epoch seconds)
}

/**
 * Signs a session payload with HMAC-SHA256.
 * Format: base64(payload).base64(signature)
 */
export function signSession(payload: SessionPayload): string {
    const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signature = crypto
        .createHmac("sha256", SESSION_SECRET)
        .update(data)
        .digest("base64url");
    return `${data}.${signature}`;
}

/**
 * Verifies and parses a signed session token.
 * Returns null if signature is invalid or payload is malformed.
 */
export function verifySession(token: string): SessionPayload | null {
    const parts = token.split(".");
    if (parts.length !== 2) return null;

    const [data, signature] = parts;

    const expectedSignature = crypto
        .createHmac("sha256", SESSION_SECRET)
        .update(data)
        .digest("base64url");

    // Constant-time comparison to prevent timing attacks
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
        return null;
    }

    try {
        const payload = JSON.parse(Buffer.from(data, "base64url").toString()) as SessionPayload;

        // Validate required fields
        if (!payload.userId || !payload.username || !payload.grade || !payload.iat) {
            return null;
        }

        // Reject sessions older than the configured lifetime.
        if (Math.floor(Date.now() / 1000) - payload.iat > SESSION_MAX_AGE) {
            return null;
        }

        return payload;
    } catch {
        return null;
    }
}
