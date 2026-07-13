package fr.whip.bot.manager.impl;

import fr.whip.api.model.Machine;
import fr.whip.api.model.User;
import fr.whip.bot.manager.base.BaseManager;
import fr.whip.bot.storage.cache.CacheDataStorage;
import fr.whip.bot.storage.hibernate.HibernateDataStorage;
import fr.whip.bot.storage.hibernate.HibernateConnection;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executors;

public class MachineManager extends BaseManager<Machine> {

    private final HibernateConnection connection;

    public MachineManager(HibernateConnection connection) {
        super(new CacheDataStorage<>(
                new HibernateDataStorage<>(connection, Machine.class),
                Executors.newSingleThreadScheduledExecutor()
        ));
        this.connection = connection;
    }

    public Optional<Machine> findByUserAndHwid(User user, String hwid) {
        return getCache().values().stream()
                .filter(m -> m.getUser() != null && Objects.equals(user.getId(), m.getUser().getId()) && m.getHwid().equals(hwid))
                .findFirst()
                .or(() -> findByUserAndHwidFromDb(user, hwid));
    }

    public List<Machine> findByUser(User user) {
        return getCache().values().stream()
                .filter(m -> m.getUser() != null && Objects.equals(user.getId(), m.getUser().getId()))
                .toList();
    }

    public List<Machine> findActiveByUser(User user) {
        return getCache().values().stream()
                .filter(m -> m.getUser() != null && Objects.equals(user.getId(), m.getUser().getId()) && !m.isRevoked())
                .toList();
    }

    public long countActiveByUser(User user) {
        return findActiveByUser(user).size();
    }

    private Optional<Machine> findByUserAndHwidFromDb(User user, String hwid) {
        try (var session = connection.getSessionFactory().openSession()) {
            return session.createQuery("FROM Machine WHERE user = :user AND hwid = :hwid", Machine.class)
                    .setParameter("user", user)
                    .setParameter("hwid", hwid)
                    .uniqueResultOptional()
                    .map(machine -> {
                        getCache().put(machine.getId(), machine);
                        return machine;
                    });
        }
    }
}