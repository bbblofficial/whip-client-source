package fr.whip.bot.manager.impl;

import fr.whip.api.model.Download;
import fr.whip.api.model.Product;
import fr.whip.api.model.User;
import fr.whip.bot.manager.base.BaseManager;
import fr.whip.bot.storage.cache.CacheDataStorage;
import fr.whip.bot.storage.hibernate.HibernateDataStorage;
import fr.whip.bot.storage.hibernate.HibernateConnection;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;

public class DownloadManager extends BaseManager<Download> {

    private final HibernateConnection connection;

    public DownloadManager(HibernateConnection connection) {
        super(new CacheDataStorage<>(
                new HibernateDataStorage<>(connection, Download.class),
                Executors.newSingleThreadScheduledExecutor()));
        this.connection = connection;
    }

    public Optional<Download> findByDownloadId(String downloadId) {
        return getCache().values().stream()
                .filter(d -> d.getDownloadId().equals(downloadId))
                .findFirst()
                .or(() -> findByDownloadIdFromDb(downloadId));
    }

    public List<Download> findByUser(User user) {
        return getCache().values().stream()
                .filter(d -> d.getUser() != null && Objects.equals(user.getId(), d.getUser().getId()))
                .toList();
    }

    public void revokeAllForUserAndProduct(User user, Product product) {
        List<Download> userDownloads = findByUser(user).stream()
                .filter(d -> !d.isRevoked())
                .filter(d -> d.getProduct() != null && Objects.equals(product.getId(), d.getProduct().getId()))
                .toList();

        for (Download download : userDownloads) {
            download.setRevoked(true);
            save(download);
        }
    }

    public String generateDownloadId() {
        return UUID.randomUUID().toString().replace("-", "").toUpperCase();
    }

    private Optional<Download> findByDownloadIdFromDb(String downloadId) {
        try (var session = connection.getSessionFactory().openSession()) {
            return session.createQuery("FROM Download WHERE downloadId = :downloadId", Download.class)
                    .setParameter("downloadId", downloadId)
                    .uniqueResultOptional()
                    .map(download -> {
                        getCache().put(download.getId(), download);
                        return download;
                    });
        }
    }
}
