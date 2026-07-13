package fr.whip.bot.manager.impl;

import fr.whip.api.model.Product;
import fr.whip.api.model.ProductType;
import fr.whip.bot.manager.base.BaseManager;
import fr.whip.bot.storage.cache.CacheDataStorage;
import fr.whip.bot.storage.hibernate.HibernateDataStorage;
import fr.whip.bot.storage.hibernate.HibernateConnection;

import java.util.Optional;
import java.util.concurrent.Executors;

public class ProductManager extends BaseManager<Product> {

    private final HibernateConnection connection;

    public ProductManager(HibernateConnection connection) {
        super(new CacheDataStorage<>(
                new HibernateDataStorage<>(connection, Product.class),
                Executors.newSingleThreadScheduledExecutor()
        ));
        this.connection = connection;

        loadAll();
    }

    public Optional<Product> findByCode(ProductType code) {
        return getCache().values().stream()
                .filter(p -> p.getCode() == code)
                .findFirst()
                .or(() -> findByCodeFromDb(code));
    }

    private Optional<Product> findByCodeFromDb(ProductType code) {
        try (var session = connection.getSessionFactory().openSession()) {
            return session.createQuery("FROM Product WHERE code = :code", Product.class)
                    .setParameter("code", code)
                    .uniqueResultOptional()
                    .map(product -> {
                        getCache().put(product.getId(), product);
                        return product;
                    });
        }
    }
}