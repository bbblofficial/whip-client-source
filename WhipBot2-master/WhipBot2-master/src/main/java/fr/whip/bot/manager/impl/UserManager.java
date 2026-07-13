package fr.whip.bot.manager.impl;

import fr.whip.api.model.User;
import fr.whip.bot.manager.base.BaseManager;
import fr.whip.bot.storage.cache.CacheDataStorage;
import fr.whip.bot.storage.hibernate.HibernateDataStorage;
import fr.whip.bot.storage.hibernate.HibernateConnection;
import org.hibernate.Session;
import org.hibernate.Transaction;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;

public class UserManager extends BaseManager<User> {

    private final HibernateConnection connection;

    public UserManager(HibernateConnection connection) {
        super(new CacheDataStorage<>(
                new HibernateDataStorage<>(connection, User.class),
                Executors.newSingleThreadScheduledExecutor()));
        this.connection = connection;
        loadAll();
    }

    public Optional<User> findByUsername(String username) {
        return getCache().values().stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst()
                .or(() -> findByUsernameFromDb(username));
    }

    public Optional<User> findById(UUID id) {
        User cached = getCache().get(id);
        if (cached != null) return Optional.of(cached);
        try (var session = connection.getSessionFactory().openSession()) {
            return session.createQuery("FROM User WHERE id = :id", User.class)
                    .setParameter("id", id)
                    .uniqueResultOptional()
                    .map(user -> {
                        getCache().put(user.getId(), user);
                        return user;
                    });
        }
    }

    /**
     * Direct, verified UPDATE of the password hash (avoids the silent
     * merge-on-detached-entity path that swallows errors). Returns true if a
     * row was actually updated, and keeps the cache in sync.
     */
    public boolean updatePassword(UUID id, String passwordHash) {
        int updated = 0;
        Transaction tx = null;
        try (Session session = connection.getSessionFactory().openSession()) {
            tx = session.beginTransaction();
            updated = session.createMutationQuery("UPDATE User SET passwordHash = :h WHERE id = :id")
                    .setParameter("h", passwordHash)
                    .setParameter("id", id)
                    .executeUpdate();
            tx.commit();
        } catch (Exception e) {
            if (tx != null) tx.rollback();
            throw new RuntimeException("Failed to update password", e);
        }
        if (updated > 0) {
            User cached = getCache().get(id);
            if (cached != null) cached.setPasswordHash(passwordHash);
        }
        return updated > 0;
    }

    public Optional<User> findByDiscordId(String discordId) {
        return getCache().values().stream()
                .filter(u -> discordId.equals(u.getDiscordId()))
                .findFirst()
                .or(() -> findByDiscordIdFromDb(discordId));
    }

    /**
     * DB-authoritative existence check for the registration path. The in-memory cache
     * can hold accounts deleted elsewhere (e.g. on the site), which would wrongly report
     * "already registered". We hit the database and evict any stale cache entry when the
     * row no longer exists.
     */
    public boolean existsByDiscordId(String discordId) {
        boolean inDb = findByDiscordIdFromDb(discordId).isPresent();
        if (!inDb)
            getCache().values().removeIf(u -> discordId.equals(u.getDiscordId()));
        return inDb;
    }

    private Optional<User> findByUsernameFromDb(String username) {
        try (var session = connection.getSessionFactory().openSession()) {
            return session.createQuery("FROM User WHERE username = :username", User.class)
                    .setParameter("username", username)
                    .uniqueResultOptional()
                    .map(user -> {
                        getCache().put(user.getId(), user);
                        return user;
                    });
        }
    }

    private Optional<User> findByDiscordIdFromDb(String discordId) {
        try (var session = connection.getSessionFactory().openSession()) {
            return session.createQuery("FROM User WHERE discordId = :discordId", User.class)
                    .setParameter("discordId", discordId)
                    .uniqueResultOptional()
                    .map(user -> {
                        getCache().put(user.getId(), user);
                        return user;
                    });
        }
    }
}