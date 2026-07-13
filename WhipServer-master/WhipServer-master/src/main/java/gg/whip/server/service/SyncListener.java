package gg.whip.server.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.postgresql.PGConnection;
import org.postgresql.PGNotification;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.UUID;

/**
 * Listens on the {@code whip_sync} Postgres notification channel and
 * reacts to admin actions taken in the WhipSite admin panel.
 *
 * <p>Today only handles the live-session-close path:
 * <pre>
 *   admin clicks "Terminer" on /admin/sessions
 *     → WhipSite closeSession() updates ended_at + pg_notify('whip_sync', '{"entity":"session","action":"close","id":"<uuid>"}')
 *     → this listener wakes up, parses the JSON, calls
 *       ConnectionPoolService.disconnectBySessionId(uuid) which closes
 *       the live Netty channel.
 * </pre>
 *
 * <p>Uses a dedicated long-lived Postgres connection (LISTEN can't share
 * the Hikari pool — it'd starve other queries). Polls every 250 ms.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SyncListener {

    private final DataSource dataSource;
    private final ConnectionPoolService connectionPool;

    private volatile boolean running = false;
    private Thread thread;

    @EventListener(ApplicationReadyEvent.class)
    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this::pollLoop, "whip-sync-listener");
        thread.setDaemon(true);
        thread.start();
        log.info("SyncListener started — listening on Postgres channel 'whip_sync'");
    }

    public void stop() {
        running = false;
        if (thread != null) thread.interrupt();
    }

    private void pollLoop() {
        while (running) {
            try (Connection raw = dataSource.getConnection()) {
                PGConnection pg = raw.unwrap(PGConnection.class);
                try (Statement listenStmt = raw.createStatement()) {
                    listenStmt.execute("LISTEN whip_sync");
                }
                log.info("LISTEN whip_sync established on backend pid={}",
                        pg.getBackendPID());

                while (running) {
                    PGNotification[] notifications = pg.getNotifications(250);
                    if (notifications == null) continue;
                    for (PGNotification n : notifications) {
                        handleNotification(n.getParameter());
                    }
                }
            } catch (Exception e) {
                log.warn("SyncListener loop crashed, retrying in 5 s: {}", e.getMessage());
                try { Thread.sleep(5000); } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    /**
     * Parse a {@code whip_sync} payload of the form
     * {@code {"entity":"session","action":"close","id":"<uuid>"}}.
     * No JSON dependency — naive substring match keeps the deps minimal.
     */
    private void handleNotification(String payload) {
        if (payload == null) return;
        log.debug("Received whip_sync notification: {}", payload);

        String entity = extractField(payload, "entity");
        String action = extractField(payload, "action");
        String id = extractField(payload, "id");

        if ("session".equals(entity) && id != null) {
            try {
                UUID sessionId = UUID.fromString(id);
                if ("close".equals(action)) {
                    boolean closed = connectionPool.disconnectBySessionId(sessionId);
                    log.info("Admin close: session={} live={}", sessionId, closed);
                } else if ("crash".equals(action)) {
                    boolean crashed = connectionPool.crashBySessionId(sessionId);
                    log.info("Admin crash: session={} delivered={}", sessionId, crashed);
                }
            } catch (IllegalArgumentException e) {
                log.warn("Bad UUID in whip_sync payload: {}", id);
            }
            return;
        }

        // entity=user, action=update — fired by WhipSite when an admin
        // changes a user's config or other identity-bound state. We
        // kick every live session of that user so they reconnect with
        // fresh data from the DB. Without this they'd keep running the
        // old config until heartbeat timeout.
        if ("user".equals(entity) && "update".equals(action) && id != null) {
            try {
                UUID userId = UUID.fromString(id);
                int kicked = connectionPool.disconnectByUserId(userId);
                if (kicked > 0) {
                    log.info("Admin user-update: kicked {} session(s) for user {}",
                            kicked, userId);
                }
            } catch (IllegalArgumentException e) {
                log.warn("Bad user UUID in whip_sync payload: {}", id);
            }
            return;
        }
        // Other entities (license/machine/download/...) are handled by
        // WhipBot's listener, not the server. Ignore them here.
    }

    /**
     * Pull a string value out of a JSON payload like
     * {@code {"entity":"session","id":"abc"}}. Naive — assumes the value
     * is a quoted string or null. Good enough for our own outbound
     * payloads which we control.
     */
    private static String extractField(String json, String key) {
        String needle = "\"" + key + "\"";
        int k = json.indexOf(needle);
        if (k < 0) return null;
        int colon = json.indexOf(':', k + needle.length());
        if (colon < 0) return null;
        int i = colon + 1;
        // skip whitespace
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        if (i >= json.length()) return null;
        if (json.charAt(i) == 'n') return null; // null
        if (json.charAt(i) != '"') return null;
        int end = json.indexOf('"', i + 1);
        if (end < 0) return null;
        return json.substring(i + 1, end);
    }
}
