package fr.whip.bot.storage.hibernate;

import fr.whip.api.storage.IIdentifiable;
import fr.whip.bot.storage.IPersistentDataStorage;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;

public class HibernateDataStorage<T extends IIdentifiable> implements IPersistentDataStorage<T> {

    private final HibernateConnection connection;
    private final Class<T> entityClass;

    public HibernateDataStorage(HibernateConnection connection, Class<T> entityClass) {
        this.connection = connection;
        this.entityClass = entityClass;
    }

    @Override
    public void start() {
    }

    @Override
    public void stop() {
    }

    @Override
    public T save(T data) {
        return executeInTransaction(session -> session.merge(data));
    }

    @Override
    public Optional<T> get(UUID id) {
        return executeInTransaction(session -> Optional.ofNullable(session.get(entityClass, id)));
    }

    @Override
    public void delete(UUID id) {
        executeInTransactionVoid(session -> {
            T entity = session.get(entityClass, id);
            if (entity != null)
                session.remove(entity);
        });
    }

    @Override
    public List<T> loadAll() {
        return executeInTransaction(
                session -> session.createQuery("FROM " + entityClass.getSimpleName(), entityClass).getResultList());
    }

    protected SessionFactory getSessionFactory() {
        return connection.getSessionFactory();
    }

    protected <R> R executeInTransaction(Function<Session, R> action) {
        try (Session session = getSessionFactory().openSession()) {
            Transaction transaction = session.beginTransaction();
            try {
                R result = action.apply(session);
                transaction.commit();
                return result;
            } catch (Exception e) {
                transaction.rollback();
                throw e;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    protected void executeInTransactionVoid(Consumer<Session> action) {
        try (Session session = getSessionFactory().openSession()) {
            Transaction transaction = session.beginTransaction();
            try {
                action.accept(session);
                transaction.commit();
            } catch (Exception e) {
                transaction.rollback();
                throw new RuntimeException("Transaction failed", e);
            }
        } catch (Exception e) {
            throw new RuntimeException("Transaction failed", e);
        }
    }
}
