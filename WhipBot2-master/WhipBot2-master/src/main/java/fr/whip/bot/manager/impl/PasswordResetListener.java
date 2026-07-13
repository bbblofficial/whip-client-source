package fr.whip.bot.manager.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.data.DatabaseData;
import fr.whip.bot.data.log.LogCategory;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.components.actionrow.ActionRow;
import net.dv8tion.jda.api.components.buttons.Button;
import org.postgresql.PGConnection;
import org.postgresql.PGNotification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.Color;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Listens on Postgres NOTIFY channels fired by the admin panel and DMs the
 * targeted user:
 *  - {@code whip_password_reset} → embed + button → modal to set a new password
 *    (link valid 30 min; the DM is removed on success or after 30 min).
 *  - {@code whip_hwid_reset} → "redownload the client" notice (auto-deleted 1 min).
 *
 * Uses a dedicated long-lived JDBC connection (LISTEN needs a persistent
 * connection, separate from the Hibernate/HikariCP pool).
 */
public class PasswordResetListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(PasswordResetListener.class);
    public static final String PASSWORD_CHANNEL = "whip_password_reset";
    public static final String HWID_CHANNEL = "whip_hwid_reset";
    public static final String BUTTON_PREFIX = "pwreset:";
    /** Password reset link validity, in seconds. */
    public static final long RESET_TTL_SECONDS = 30 * 60;

    private final WhipBot main;
    private final DatabaseData db;
    private volatile boolean running;
    private Thread thread;
    private Connection connection;

    public PasswordResetListener(WhipBot main, DatabaseData db) {
        this.main = main;
        this.db = db;
    }

    public void start() {
        running = true;
        thread = new Thread(this::loop, "pwreset-listener");
        thread.setDaemon(true);
        thread.start();
    }

    private void loop() {
        while (running) {
            try {
                String url = "jdbc:postgresql://" + db.host() + ":" + db.port() + "/" + db.database();
                connection = DriverManager.getConnection(url, db.username(), db.password());
                try (Statement st = connection.createStatement()) {
                    st.execute("LISTEN " + PASSWORD_CHANNEL);
                    st.execute("LISTEN " + HWID_CHANNEL);
                }
                LOGGER.info("Listening on Postgres channels '{}' and '{}'", PASSWORD_CHANNEL, HWID_CHANNEL);
                PGConnection pg = connection.unwrap(PGConnection.class);
                while (running) {
                    PGNotification[] notifications = pg.getNotifications(10000); // block up to 10s
                    if (notifications != null) {
                        for (PGNotification n : notifications) {
                            route(n.getName(), n.getParameter());
                        }
                    }
                }
            } catch (Exception e) {
                if (running) {
                    LOGGER.error("Notify listener error, reconnecting in 5s: {}", e.getMessage());
                    closeConnection();
                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            } finally {
                closeConnection();
            }
        }
    }

    private void route(String channel, String payload) {
        if (PASSWORD_CHANNEL.equals(channel)) handlePasswordReset(payload);
        else if (HWID_CHANNEL.equals(channel)) handleHwidReset(payload);
    }

    private void handlePasswordReset(String userIdStr) {
        withUser(userIdStr, (user, discordId) -> {
            long expiry = (System.currentTimeMillis() / 1000) + RESET_TTL_SECONDS;
            EmbedBuilder embed = new EmbedBuilder()
                    .setTitle("🔑 Password Reset")
                    .setColor(Color.decode("#3498db"))
                    .setThumbnail(main.getJda().getSelfUser().getEffectiveAvatarUrl())
                    .setDescription("An administrator requested a password reset for your account.\n\n"
                            + "Click the button below to set a **new password**.\n⏱️ This link expires in **30 minutes**.")
                    .setFooter("Whip Client");
            Button button = Button.primary(BUTTON_PREFIX + user.getId() + ":" + expiry, "Set my password");
            main.getJda().retrieveUserById(discordId).queue(
                    u -> u.openPrivateChannel().queue(
                            pc -> pc.sendMessageEmbeds(embed.build()).setComponents(ActionRow.of(button)).queue(
                                    msg -> {
                                        main.getLogManager().info(LogCategory.AUTH, discordId,
                                                "Password reset DM sent to " + user.getUsername());
                                        // Fallback cleanup if the user never uses the link.
                                        msg.delete().queueAfter(30, TimeUnit.MINUTES, s -> {}, t -> {});
                                    },
                                    err -> LOGGER.warn("Could not DM {}: {}", user.getUsername(), err.getMessage())),
                            err -> LOGGER.warn("Could not open DM with {}: {}", discordId, err.getMessage())),
                    err -> LOGGER.warn("Could not retrieve Discord user {}: {}", discordId, err.getMessage()));
        });
    }

    private void handleHwidReset(String userIdStr) {
        withUser(userIdStr, (user, discordId) -> {
            EmbedBuilder embed = new EmbedBuilder()
                    .setTitle("🔄 HWID Reset")
                    .setColor(Color.decode("#3498db"))
                    .setThumbnail(main.getJda().getSelfUser().getEffectiveAvatarUrl())
                    .setDescription("Your HWID has been reset.\nPlease **redownload the client** to bind your new hardware.")
                    .setFooter("Whip Client");
            main.getJda().retrieveUserById(discordId).queue(
                    u -> u.openPrivateChannel().queue(
                            pc -> pc.sendMessageEmbeds(embed.build()).queue(
                                    msg -> msg.delete().queueAfter(1, TimeUnit.MINUTES, s -> {}, t -> {}),
                                    err -> LOGGER.warn("Could not DM {}: {}", user.getUsername(), err.getMessage())),
                            err -> LOGGER.warn("Could not open DM with {}: {}", discordId, err.getMessage())),
                    err -> LOGGER.warn("Could not retrieve Discord user {}: {}", discordId, err.getMessage()));
        });
    }

    private interface UserAction {
        void run(fr.whip.api.model.User user, String discordId);
    }

    private void withUser(String userIdStr, UserAction action) {
        try {
            UUID userId = UUID.fromString(userIdStr.trim());
            main.getUserManager().findById(userId).ifPresentOrElse(user -> {
                String discordId = user.getDiscordId();
                if (discordId == null || discordId.isEmpty()) {
                    LOGGER.warn("Notify for {} but no Discord linked", user.getUsername());
                    return;
                }
                action.run(user, discordId);
            }, () -> LOGGER.warn("Notify for unknown user id {}", userId));
        } catch (Exception e) {
            LOGGER.error("Failed to handle notification '{}': {}", userIdStr, e.getMessage());
        }
    }

    private void closeConnection() {
        if (connection != null) {
            try {
                connection.close();
            } catch (Exception ignored) {
            }
            connection = null;
        }
    }

    public void stop() {
        running = false;
        if (thread != null) thread.interrupt();
        closeConnection();
    }
}
