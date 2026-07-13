package fr.whip.bot.storage.sync;

import com.fasterxml.jackson.databind.ObjectMapper;
import fr.whip.bot.data.DatabaseData;
import fr.whip.bot.manager.impl.*;
import org.postgresql.PGConnection;
import org.postgresql.PGNotification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.UUID;

public class SyncListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(SyncListener.class);
    private static final String CHANNEL = "whip_sync";
    private static final int POLL_INTERVAL_MS = 2000;
    private static final int RECONNECT_DELAY_MS = 5000;

    private final DatabaseData config;
    private final UserManager userManager;
    private final ProductManager productManager;
    private final LicenseManager licenseManager;
    private final MachineManager machineManager;
    private final DownloadManager downloadManager;
    private final ObjectMapper objectMapper;

    private volatile boolean running;
    private Thread listenerThread;
    private Connection connection;

    public SyncListener(DatabaseData config,
                        UserManager userManager,
                        ProductManager productManager,
                        LicenseManager licenseManager,
                        MachineManager machineManager,
                        DownloadManager downloadManager) {
        this.config = config;
        this.userManager = userManager;
        this.productManager = productManager;
        this.licenseManager = licenseManager;
        this.machineManager = machineManager;
        this.downloadManager = downloadManager;
        this.objectMapper = new ObjectMapper();
    }

    public void start() {
        running = true;
        listenerThread = new Thread(this::listenLoop, "SyncListener");
        listenerThread.setDaemon(true);
        listenerThread.start();
        LOGGER.info("SyncListener started on channel '{}'", CHANNEL);
    }

    public void stop() {
        running = false;
        if (listenerThread != null) {
            listenerThread.interrupt();
        }
        closeConnection();
        LOGGER.info("SyncListener stopped");
    }

    private void listenLoop() {
        while (running) {
            try {
                ensureConnection();
                pollNotifications();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                LOGGER.warn("SyncListener error, reconnecting in {}ms: {}", RECONNECT_DELAY_MS, e.getMessage());
                closeConnection();
                try {
                    Thread.sleep(RECONNECT_DELAY_MS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    private void ensureConnection() throws Exception {
        if (connection != null && !connection.isClosed()) {
            return;
        }

        String url = "jdbc:postgresql://" + config.host() + ":" + config.port() + "/" + config.database();
        connection = DriverManager.getConnection(url, config.username(), config.password());
        connection.setAutoCommit(true);

        try (Statement stmt = connection.createStatement()) {
            stmt.execute("LISTEN " + CHANNEL);
        }

        LOGGER.info("SyncListener connected and listening on '{}'", CHANNEL);
    }

    private void pollNotifications() throws Exception {
        PGConnection pgConn = connection.unwrap(PGConnection.class);
        PGNotification[] notifications = pgConn.getNotifications(POLL_INTERVAL_MS);
        if (notifications == null) {
            return;
        }

        for (PGNotification notification : notifications) {
            try {
                SyncPayload sync = objectMapper.readValue(notification.getParameter(), SyncPayload.class);
                String entity = sync.entity();
                String action = sync.action();
                String id = sync.id();

                LOGGER.info("Sync received: entity={}, action={}, id={}", entity, action, id);

                switch (entity) {
                    case "user" -> handleSync(userManager, action, id);
                    case "product" -> handleSync(productManager, action, id);
                    case "license" -> handleSync(licenseManager, action, id);
                    case "machine" -> handleSync(machineManager, action, id);
                    case "download" -> handleSync(downloadManager, action, id);
                    default -> LOGGER.warn("Unknown sync entity: {}", entity);
                }
            } catch (Exception e) {
                LOGGER.error("Failed to handle sync notification: {}", notification.getParameter(), e);
            }
        }
    }

    private void handleSync(fr.whip.bot.manager.base.BaseManager<?> manager, String action, String id) {
        if (id == null || id.isEmpty()) {
            manager.loadAll();
            LOGGER.info("Reloaded all entries for manager (no ID provided)");
            return;
        }

        UUID uuid = UUID.fromString(id);

        switch (action) {
            case "delete" -> {
                manager.getStorage().evict(uuid);
                LOGGER.debug("Evicted {} from cache", uuid);
            }
            case "update" -> {
                manager.getStorage().refresh(uuid);
                LOGGER.debug("Refreshed {} in cache", uuid);
            }
            case "create" -> {
                manager.get(uuid);
                LOGGER.debug("Loaded {} into cache", uuid);
            }
            default -> LOGGER.warn("Unknown sync action: {}", action);
        }
    }

    private void closeConnection() {
        if (connection != null) {
            try {
                connection.close();
            } catch (Exception e) {
                LOGGER.debug("Error closing sync connection", e);
            }
            connection = null;
        }
    }
}