package fr.whip.bot.manager.impl;

import fr.whip.api.model.License;
import fr.whip.api.model.LicenseStatus;
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

public class LicenseManager extends BaseManager<License> {

    private final HibernateConnection connection;

    public LicenseManager(HibernateConnection connection) {
        super(new CacheDataStorage<>(
                new HibernateDataStorage<>(connection, License.class),
                Executors.newSingleThreadScheduledExecutor()));
        this.connection = connection;
        loadAll();
    }

    public Optional<License> findByLicenseKey(String licenseKey) {
        return getCache().values().stream()
                .filter(l -> l.getLicenseKey().equals(licenseKey))
                .findFirst()
                .or(() -> findByLicenseKeyFromDb(licenseKey));
    }

    /**
     * Reads the license straight from the database (bypassing the possibly stale cache)
     * and refreshes the cached copy. Used on the registration path where the user link
     * must reflect the current DB state — a cached license may still point at a user that
     * was deleted elsewhere (the FK is set to NULL on delete).
     */
    public Optional<License> findByLicenseKeyFresh(String licenseKey) {
        return findByLicenseKeyFromDb(licenseKey);
    }

    public List<License> findByUser(User user) {
        return getCache().values().stream()
                .filter(l -> l.getUser() != null && Objects.equals(user.getId(), l.getUser().getId()))
                .toList();
    }

    public List<License> findByUserAndStatus(User user, LicenseStatus status) {
        return getCache().values().stream()
                .filter(l -> l.getUser() != null && Objects.equals(user.getId(), l.getUser().getId())
                        && l.getStatus() == status)
                .toList();
    }

    private Optional<License> findByLicenseKeyFromDb(String licenseKey) {
        try (var session = connection.getSessionFactory().openSession()) {
            return session.createQuery("FROM License WHERE licenseKey = :licenseKey", License.class)
                    .setParameter("licenseKey", licenseKey)
                    .uniqueResultOptional()
                    .map(license -> {
                        getCache().put(license.getId(), license);
                        return license;
                    });
        }
    }

    public String generateLicenseKey() {
        String uuid = UUID.randomUUID().toString().toUpperCase().replace("-", "");
        return "WHIP-" + uuid.substring(0, 4) + "-" + uuid.substring(4, 8) + "-" +
                uuid.substring(8, 12) + "-" + uuid.substring(12, 16);
    }
}