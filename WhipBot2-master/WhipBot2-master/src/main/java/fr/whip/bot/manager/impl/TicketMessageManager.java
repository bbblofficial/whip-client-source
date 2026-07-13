package fr.whip.bot.manager.impl;

import fr.whip.bot.data.entity.TicketMessage;
import fr.whip.bot.storage.hibernate.HibernateConnection;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class TicketMessageManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(TicketMessageManager.class);

    private final HibernateConnection connection;
    private final ExecutorService writer = Executors.newSingleThreadExecutor(r -> new Thread(r, "ticket-msg-writer"));

    public TicketMessageManager(HibernateConnection connection) {
        this.connection = connection;
    }

    public void save(TicketMessage message) {
        writer.submit(() -> persist(message));
    }

    public List<TicketMessage> findByTicket(String ticketUserId) {
        try (Session session = connection.getSessionFactory().openSession()) {
            return session.createQuery(
                    "FROM TicketMessage WHERE ticketUserId = :uid ORDER BY timestamp ASC",
                    TicketMessage.class)
                    .setParameter("uid", ticketUserId)
                    .list();
        } catch (Exception e) {
            LOGGER.error("Failed to fetch ticket messages for {}", ticketUserId, e);
            return List.of();
        }
    }

    private void persist(TicketMessage message) {
        Transaction tx = null;
        try (Session session = connection.getSessionFactory().openSession()) {
            tx = session.beginTransaction();
            session.persist(message);
            tx.commit();
        } catch (Exception e) {
            if (tx != null) tx.rollback();
            LOGGER.error("Failed to persist ticket message", e);
        }
    }

    public void stop() {
        writer.shutdown();
    }
}
