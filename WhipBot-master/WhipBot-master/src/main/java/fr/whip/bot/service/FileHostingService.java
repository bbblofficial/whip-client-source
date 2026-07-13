package fr.whip.bot.service;

import io.javalin.Javalin;
import io.javalin.http.ContentType;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class FileHostingService {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileHostingService.class);
    private static final long LINK_EXPIRATION_MS = 60_000; // 1 minute
    private static final int CLEANUP_INTERVAL_SECONDS = 30;

    private final Javalin server;
    private final Map<String, TemporaryFileLink> activeLinks;
    private final ScheduledExecutorService cleanupScheduler;
    private final int port;
    private final String baseUrl;

    public FileHostingService(int port, String baseUrl) {
        this.port = port;
        this.baseUrl = baseUrl;
        this.activeLinks = new ConcurrentHashMap<>();
        this.cleanupScheduler = Executors.newSingleThreadScheduledExecutor();
        this.server = Javalin.create(config -> {
            config.showJavalinBanner = false;
        });

        setupRoutes();
        startCleanupTask();
    }

    private void setupRoutes() {
        server.get("/download/{token}", this::handleDownload);

        server.get("/health", ctx -> ctx.result("OK"));
    }

    private void handleDownload(Context ctx) {
        String token = ctx.pathParam("token");

        // Block Discord bot previews
        String userAgent = ctx.header("User-Agent");
        if (userAgent != null && (userAgent.contains("Discordbot") || userAgent.contains("discord"))) {
            ctx.status(403).result("Bot access forbidden");
            LOGGER.warn("Blocked bot access attempt: {}", userAgent);
            return;
        }

        TemporaryFileLink link = activeLinks.get(token);

        if (link == null) {
            ctx.status(404).result("Link not found or expired");
            LOGGER.warn("Download attempt with invalid token: {}", token);
            return;
        }

        if (link.isExpired()) {
            activeLinks.remove(token);
            ctx.status(410).result("Link has expired");
            LOGGER.warn("Download attempt with expired token: {}", token);
            return;
        }

        link.markAsUsed();
        activeLinks.remove(token);

        byte[] fileData = link.getFileData();

        ctx.status(200)
           .contentType(ContentType.APPLICATION_OCTET_STREAM)
           .header("Content-Disposition", "attachment; filename=\"" + link.getFileName() + "\"")
           .header("Content-Length", String.valueOf(fileData.length))
           .header("Cache-Control", "no-cache, no-store, must-revalidate")
           .header("Pragma", "no-cache")
           .header("Expires", "0")
           .header("X-Content-Type-Options", "nosniff")
           .result(fileData);

        LOGGER.info("File downloaded successfully: {} ({} bytes, token: {})",
                    link.getFileName(), fileData.length, token);
    }

    public String createTemporaryLink(byte[] fileData, String fileName) {
        String token = UUID.randomUUID().toString().replace("-", "");
        TemporaryFileLink link = new TemporaryFileLink(token, fileData, fileName, LINK_EXPIRATION_MS);

        activeLinks.put(token, link);

        String downloadUrl = baseUrl + "/download/" + token;
        LOGGER.info("Created temporary download link: {} (expires in 1 minute)", downloadUrl);

        return downloadUrl;
    }

    private void startCleanupTask() {
        cleanupScheduler.scheduleAtFixedRate(() -> {
            try {
                int removed = 0;
                for (Map.Entry<String, TemporaryFileLink> entry : activeLinks.entrySet()) {
                    if (entry.getValue().isExpired()) {
                        activeLinks.remove(entry.getKey());
                        removed++;
                    }
                }
                if (removed > 0) {
                    LOGGER.debug("Cleaned up {} expired download links", removed);
                }
            } catch (Exception e) {
                LOGGER.error("Error during cleanup task", e);
            }
        }, CLEANUP_INTERVAL_SECONDS, CLEANUP_INTERVAL_SECONDS, TimeUnit.SECONDS);
    }

    public void start() {
        server.start(port);
        LOGGER.info("File hosting service started on port {}", port);
    }

    public void stop() {
        cleanupScheduler.shutdown();
        server.stop();
        LOGGER.info("File hosting service stopped");
    }

    public int getActiveLinksCount() {
        return activeLinks.size();
    }
}
