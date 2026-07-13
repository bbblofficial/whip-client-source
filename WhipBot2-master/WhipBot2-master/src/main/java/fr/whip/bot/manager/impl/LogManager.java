package fr.whip.bot.manager.impl;

import fr.whip.bot.data.log.LogCategory;
import fr.whip.bot.data.log.LogEntry;
import fr.whip.bot.data.log.LogLevel;
import fr.whip.bot.storage.hibernate.HibernateConnection;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class LogManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(LogManager.class);
    private static final int RETENTION_DAYS = 90;

    private final HibernateConnection connection;
    private final ExecutorService writeExecutor;
    private final ScheduledExecutorService cleanupScheduler;

    public LogManager(HibernateConnection connection) {
        this.connection      = connection;
        this.writeExecutor   = Executors.newSingleThreadExecutor(r -> new Thread(r, "log-writer"));
        this.cleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> new Thread(r, "log-cleanup"));
        cleanupScheduler.scheduleAtFixedRate(this::deleteOldLogs, 1, 24, TimeUnit.HOURS);
    }

    public void log(LogLevel level, LogCategory category, String message) {
        log(level, category, null, message);
    }

    public void log(LogLevel level, LogCategory category, String userId, String message) {
        LogEntry entry = new LogEntry(level, category, userId, message);
        writeExecutor.submit(() -> persist(entry));
    }

    public void info(LogCategory category, String message) {
        log(LogLevel.INFO, category, message);
    }

    public void info(LogCategory category, String userId, String message) {
        log(LogLevel.INFO, category, userId, message);
    }

    public void warn(LogCategory category, String userId, String message) {
        log(LogLevel.WARN, category, userId, message);
    }

    public void error(LogCategory category, String userId, String message) {
        log(LogLevel.ERROR, category, userId, message);
    }

    public List<LogEntry> getRecent(int limit) {
        try (Session session = connection.getSessionFactory().openSession()) {
            return session.createQuery("FROM LogEntry ORDER BY timestamp DESC", LogEntry.class)
                    .setMaxResults(limit)
                    .list();
        } catch (Exception e) {
            LOGGER.error("Failed to query recent logs", e);
            return List.of();
        }
    }

    public List<LogEntry> getByCategory(LogCategory category, int limit) {
        try (Session session = connection.getSessionFactory().openSession()) {
            return session.createQuery("FROM LogEntry WHERE category = :cat ORDER BY timestamp DESC", LogEntry.class)
                    .setParameter("cat", category)
                    .setMaxResults(limit)
                    .list();
        } catch (Exception e) {
            LOGGER.error("Failed to query logs by category", e);
            return List.of();
        }
    }

    public List<LogEntry> getByUser(String userId, int limit) {
        try (Session session = connection.getSessionFactory().openSession()) {
            return session.createQuery("FROM LogEntry WHERE userId = :uid ORDER BY timestamp DESC", LogEntry.class)
                    .setParameter("uid", userId)
                    .setMaxResults(limit)
                    .list();
        } catch (Exception e) {
            LOGGER.error("Failed to query logs by user", e);
            return List.of();
        }
    }

    private void persist(LogEntry entry) {
        Transaction tx = null;
        try (Session session = connection.getSessionFactory().openSession()) {
            tx = session.beginTransaction();
            session.persist(entry);
            tx.commit();
        } catch (Exception e) {
            if (tx != null) tx.rollback();
            LOGGER.error("Failed to persist log entry", e);
        }
    }

    private void deleteOldLogs() {
        Transaction tx = null;
        try (Session session = connection.getSessionFactory().openSession()) {
            tx = session.beginTransaction();
            Instant cutoff = Instant.now().minus(RETENTION_DAYS, ChronoUnit.DAYS);
            int deleted = session.createMutationQuery("DELETE FROM LogEntry WHERE timestamp < :cutoff")
                    .setParameter("cutoff", cutoff)
                    .executeUpdate();
            tx.commit();
            if (deleted > 0) LOGGER.info("Deleted {} log entries older than {} days", deleted, RETENTION_DAYS);
        } catch (Exception e) {
            if (tx != null) tx.rollback();
            LOGGER.error("Failed to clean up old logs", e);
        }
    }

    public void stop() {
        writeExecutor.shutdown();
        cleanupScheduler.shutdown();
    }
}
