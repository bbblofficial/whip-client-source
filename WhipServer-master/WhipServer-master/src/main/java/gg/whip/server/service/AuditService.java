package gg.whip.server.service;

import gg.whip.server.model.AuditLog;
import gg.whip.server.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Writes audit/journal rows into the shared {@code audit_logs} table.
 *
 * - SYSTEM events (server start/stop) → admin_id = entity_id = null, no IP.
 * - CLIENT events (auth steps, download, connection) → entity_id = the user id
 *   (when known) + the source IP, so the panel attributes them to the user
 *   instead of "Système".
 *
 * Writes happen on a dedicated daemon thread so they never block the Netty
 * event loop; use {@link #systemSync} for shutdown. Never throws.
 */
@Service
@RequiredArgsConstructor
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditLogRepository repository;

    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "audit-logger");
        t.setDaemon(true);
        return t;
    });

    /** System event (no admin, no entity, no IP), written asynchronously. */
    public void system(String action, String entity, String details) {
        submit(null, action, entity, null, null, details);
    }

    /** Synchronous system event — for shutdown, where async may not flush. */
    public void systemSync(String action, String entity, String details) {
        write(null, action, entity, null, null, details);
    }

    /** Client-attributed event: entityId = user id (nullable pre-auth), with IP. */
    public void event(String action, String entity, UUID entityId, String ip, String details) {
        submit(null, action, entity, entityId, ip, details);
    }

    private void submit(UUID adminId, String action, String entity, UUID entityId, String ip, String details) {
        try {
            executor.submit(() -> write(adminId, action, entity, entityId, ip, details));
        } catch (Exception e) {
            log.warn("Failed to queue audit log: {}", e.getMessage());
        }
    }

    private void write(UUID adminId, String action, String entity, UUID entityId, String ip, String details) {
        try {
            AuditLog entry = new AuditLog();
            entry.setAdminId(adminId);
            entry.setAction(action);
            entry.setEntity(entity);
            entry.setEntityId(entityId);
            entry.setIp(ip);
            entry.setDetails(truncate(details));
            repository.save(entry);
        } catch (Exception e) {
            log.warn("Failed to write audit log ({} / {}): {}", action, entity, e.getMessage());
        }
    }

    private static String truncate(String s) {
        if (s == null) return null;
        return s.length() > 1000 ? s.substring(0, 1000) : s;
    }
}
