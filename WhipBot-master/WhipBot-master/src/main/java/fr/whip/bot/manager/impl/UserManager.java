package fr.whip.bot.manager.impl;

import fr.whip.api.model.User;
import fr.whip.bot.manager.base.BaseManager;
import fr.whip.bot.storage.cache.CacheDataStorage;
import fr.whip.bot.storage.hibernate.HibernateDataStorage;
import fr.whip.bot.storage.hibernate.HibernateConnection;

import java.util.Optional;
import java.util.concurrent.Executors;

public class UserManager extends BaseManager<User> {

    private final HibernateConnection connection;

    public UserManager(HibernateConnection connection) {
        super(new CacheDataStorage<>(
                new HibernateDataStorage<>(connection, User.class),
                Executors.newSingleThreadScheduledExecutor()
        ));
        this.connection = connection;
        loadAll();
    }

    public Optional<User> findByUsername(String username) {
        return getCache().values().stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst()
                .or(() -> findByUsernameFromDb(username));
    }

    public Optional<User> findByDiscordId(String discordId) {
        return getCache().values().stream()
                .filter(u -> discordId.equals(u.getDiscordId()))
                .findFirst()
                .or(() -> findByDiscordIdFromDb(discordId));
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