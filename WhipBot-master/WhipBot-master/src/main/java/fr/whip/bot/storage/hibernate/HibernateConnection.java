package fr.whip.bot.storage.hibernate;

import fr.whip.api.model.*;
import fr.whip.bot.data.DatabaseData;
import fr.whip.bot.storage.IConnectionDataStorage;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

public class HibernateConnection implements IConnectionDataStorage {

    private static final Logger LOGGER = LoggerFactory.getLogger(HibernateConnection.class);

    private final DatabaseData config;
    private SessionFactory sessionFactory;

    public HibernateConnection(DatabaseData config) {
        this.config = config;
    }

    @Override
    public void connect() {
        Properties properties = new Properties();

        properties.setProperty("hibernate.connection.driver_class", "org.postgresql.Driver");
        properties.setProperty("hibernate.connection.url",
                "jdbc:postgresql://" + config.host() + ":" + config.port() + "/" + config.database());
        properties.setProperty("hibernate.connection.username", config.username());
        properties.setProperty("hibernate.connection.password", config.password());

        properties.setProperty("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
        properties.setProperty("hibernate.hbm2ddl.auto", "update");
        properties.setProperty("hibernate.show_sql", "false");

        properties.setProperty("hibernate.connection.provider_class",
                "org.hibernate.hikaricp.internal.HikariCPConnectionProvider");
        properties.setProperty("hibernate.hikari.minimumIdle", "2");
        properties.setProperty("hibernate.hikari.maximumPoolSize", "10");
        properties.setProperty("hibernate.hikari.idleTimeout", "300000");

        Configuration configuration = new Configuration();
        configuration.setProperties(properties);
        configuration.addAnnotatedClass(User.class);
        configuration.addAnnotatedClass(Product.class);
        configuration.addAnnotatedClass(License.class);
        configuration.addAnnotatedClass(Machine.class);
        configuration.addAnnotatedClass(Download.class);

        this.sessionFactory = configuration.buildSessionFactory();
        LOGGER.info("Hibernate connected to {}:{}/{}", config.host(), config.port(), config.database());
    }

    @Override
    public void close() {
        if (sessionFactory != null && !sessionFactory.isClosed()) {
            sessionFactory.close();
            LOGGER.info("Hibernate connection closed");
        }
    }

    @Override
    public boolean isConnected() {
        if (sessionFactory == null || sessionFactory.isClosed()) {
            return false;
        }
        try (var session = sessionFactory.openSession()) {
            session.doWork(connection -> {
                if (!connection.isValid(5)) {
                    throw new RuntimeException("Connection invalid");
                }
            });
            return true;
        } catch (Exception e) {
            LOGGER.error("Connection check failed", e);
            return false;
        }
    }

    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }
}