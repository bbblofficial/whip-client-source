package fr.whip.bot.manager.impl;

import fr.whip.bot.data.log.AuditLog;
import fr.whip.bot.storage.hibernate.HibernateConnection;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Writes the bot's system events into the shared {@code audit_logs} table so
 * they show up in the admin panel's journal (admin_id = entity_id = null).
 * Async on a dedicated thread; {@link #systemSync} for shutdown.
 */
public class AuditManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuditManager.class);

    private final HibernateConnection connection;
    private final ExecutorService writeExecutor;

    public AuditManager(HibernateConnection connection) {
        this.connection = connection;
        this.writeExecutor = Executors.newSingleThreadExecutor(r -> new Thread(r, "audit-writer"));
    }

    public void system(String action, String entity, String details) {
        AuditLog entry = new AuditLog(action, entity, details);
        writeExecutor.submit(() -> persist(entry));
    }

    public void systemSync(String action, String entity, String details) {
        persist(new AuditLog(action, entity, details));
    }

    /** Event attributed to a user (entity_id = user id), written asynchronously. */
    public void event(String action, String entity, UUID entityId, String details) {
        AuditLog entry = new AuditLog(action, entity, details);
        entry.setEntityId(entityId);
        writeExecutor.submit(() -> persist(entry));
    }

    private void persist(AuditLog entry) {
        Transaction tx = null;
        try (Session session = connection.getSessionFactory().openSession()) {
            tx = session.beginTransaction();
            session.persist(entry);
            tx.commit();
        } catch (Exception e) {
            if (tx != null) tx.rollback();
            LOGGER.error("Failed to persist audit log", e);
        }
    }

    public void stop() {
        writeExecutor.shutdown();
    }
}
