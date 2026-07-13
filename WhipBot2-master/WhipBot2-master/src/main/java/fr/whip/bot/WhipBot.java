package fr.whip.bot;

import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.handler.*;
import fr.whip.bot.listener.AutoDetectListener;
import fr.whip.bot.listener.CommandListener;
import fr.whip.bot.listener.ComponentListener;
import fr.whip.bot.listener.FeedbackListener;
import fr.whip.bot.listener.PrivateDmListener;
import fr.whip.bot.listener.PrefixCommandListener;
import fr.whip.bot.listener.TicketMessageListener;
import fr.whip.bot.listener.GuildJoinListener;
import fr.whip.bot.listener.TicketPanelListener;
import fr.whip.bot.command.impl.DetectCommand;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.manager.impl.*;
import fr.whip.bot.service.FileHostingService;
import fr.whip.bot.data.log.LogCategory;
import fr.whip.bot.data.log.LogLevel;
import fr.whip.bot.storage.hibernate.HibernateConnection;
import net.dv8tion.jda.api.JDA;
import net.dv8tion.jda.api.JDABuilder;
import net.dv8tion.jda.api.requests.GatewayIntent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

public class WhipBot {

    private static final Logger LOGGER = LoggerFactory.getLogger(WhipBot.class);

    private final Path dataFolder;

    private volatile boolean running;
    private JDA jda;

    private ConfigHandler configHandler;
    private ConnectionHandler connectionHandler;
    private ListenerHandler listenerHandler;
    private CommandHandler commandHandler;
    private ComponentHandler componentHandler;

    private UserManager userManager;
    private ProductManager productManager;
    private LicenseManager licenseManager;
    private TicketManager ticketManager;
    private DownloadManager downloadManager;
    private CryptoManager cryptoManager;
    private TranscriptManager transcriptManager;
    private DashboardManager dashboardManager;
    private FileHostingService fileHostingService;
    private LogManager logManager;
    private AuditManager auditManager;
    private PasswordResetListener passwordResetListener;
    private TicketMessageManager ticketMessageManager;

    public WhipBot(Path dataFolder) {
        this.dataFolder = dataFolder;
    }

    public void onEnable() {
        LOGGER.info("Enabling WhipBot...");

        this.configHandler = new ConfigHandler();
        this.configHandler.init(dataFolder);
        this.configHandler.load();

        ConfigData config = configHandler.getPrototypeConfig(BotConfigLoader.class);

        this.connectionHandler = new ConnectionHandler(1);
        this.connectionHandler.init(new HibernateConnection(config.database()));

        HibernateConnection hibernate = connectionHandler.get(HibernateConnection.class);
        if (!hibernate.isConnected()) {
            LOGGER.error("Failed to connect to database");
            return;
        }

        LOGGER.info("Connected to database successfully");

        this.logManager = new LogManager(hibernate);
        this.auditManager = new AuditManager(hibernate);
        this.ticketMessageManager = new TicketMessageManager(hibernate);
        this.userManager = new UserManager(hibernate);
        this.productManager = new ProductManager(hibernate);
        this.licenseManager = new LicenseManager(hibernate);
        this.ticketManager = new TicketManager(this, hibernate);
        this.downloadManager = new DownloadManager(hibernate);
        this.cryptoManager = new CryptoManager();
        this.transcriptManager = new TranscriptManager();
        this.dashboardManager = new DashboardManager(this);

        this.userManager.start();
        this.productManager.start();
        this.licenseManager.start();
        this.downloadManager.start();
        this.cryptoManager.start();

        if (config.fileHosting().enabled()) {
            this.fileHostingService = new FileHostingService(
                    config.fileHosting().port(),
                    config.fileHosting().baseUrl());
            this.fileHostingService.start();
        }

        try {
            this.jda = JDABuilder.createDefault(config.token())
                    .enableIntents(GatewayIntent.GUILD_MEMBERS, GatewayIntent.MESSAGE_CONTENT,
                            GatewayIntent.DIRECT_MESSAGES, GatewayIntent.DIRECT_MESSAGE_TYPING,
                            GatewayIntent.GUILD_MESSAGES, GatewayIntent.GUILD_MESSAGE_REACTIONS,
                            GatewayIntent.GUILD_MESSAGE_TYPING)
                    .build()
                    .awaitReady();
        } catch (InterruptedException e) {
            LOGGER.error("Failed to initialize JDA", e);
            Thread.currentThread().interrupt();
            return;
        }

        this.ticketManager.start(this.jda);
        this.dashboardManager.start(this.jda);

        LOGGER.info("JDA connected successfully");

        String applicationId = jda.getSelfUser().getApplicationId();
        if (applicationId != null) {
            LOGGER.info("Bot invite link: https://discord.com/oauth2/authorize?client_id={}&scope=bot+applications.commands&permissions=8", applicationId);
        }

        this.listenerHandler = new ListenerHandler();
        this.listenerHandler.init(this);

        this.componentHandler = new ComponentHandler();
        this.commandHandler = new CommandHandler();

        AutoDetectListener autoDetectListener = new AutoDetectListener(this);
        this.listenerHandler.register(new CommandListener(this));
        this.listenerHandler.register(new ComponentListener(this));
        this.listenerHandler.register(new TicketMessageListener(this));
        this.listenerHandler.register(new FeedbackListener(this));
        this.listenerHandler.register(new TicketPanelListener(this));
        this.listenerHandler.register(new PrivateDmListener(this));
        this.listenerHandler.register(new PrefixCommandListener(this));
        this.listenerHandler.register(new GuildJoinListener(this));
        this.listenerHandler.register(autoDetectListener);

        // Run detection once on startup for the already-configured guild (if any).
        String configuredGuildId = config.channels().guildId();
        if (configuredGuildId != null && !configuredGuildId.isBlank()) {
            net.dv8tion.jda.api.entities.Guild startupGuild = this.jda.getGuildById(configuredGuildId);
            if (startupGuild != null) {
                autoDetectListener.silentDetect(startupGuild);
            }
        }

        this.commandHandler.init(this);

        this.passwordResetListener = new PasswordResetListener(this, config.database());
        this.passwordResetListener.start();

        this.running = true;
        this.auditManager.system("bot.start", "bot", "WhipBot démarré et connecté à Discord");
        LOGGER.info("WhipBot enabled successfully!");
    }

    public void onDisable() {
        LOGGER.info("Disabling WhipBot...");

        if (passwordResetListener != null)
            passwordResetListener.stop();
        if (auditManager != null) {
            auditManager.systemSync("bot.stop", "bot", "Arrêt du WhipBot");
            auditManager.stop();
        }
        if (logManager != null)
            logManager.stop();
        if (ticketMessageManager != null)
            ticketMessageManager.stop();
        if (fileHostingService != null)
            fileHostingService.stop();
        if (jda != null)
            jda.shutdown();
        if (userManager != null)
            userManager.stop();
        if (productManager != null)
            productManager.stop();
        if (licenseManager != null)
            licenseManager.stop();
        if (ticketManager != null)
            ticketManager.stop();
        if (downloadManager != null)
            downloadManager.stop();
        if (cryptoManager != null)
            cryptoManager.stop();
        if (dashboardManager != null)
            dashboardManager.stop();
        if (connectionHandler != null)
            connectionHandler.stop();
        if (configHandler != null)
            configHandler.clear();

        this.running = false;
        LOGGER.info("WhipBot disabled");
    }

    public boolean isRunning() {
        return running;
    }

    public JDA getJda() {
        return jda;
    }

    public ConfigHandler getConfigHandler() {
        return configHandler;
    }

    public ConnectionHandler getConnectionHandler() {
        return connectionHandler;
    }

    public ListenerHandler getListenerHandler() {
        return listenerHandler;
    }

    public CommandHandler getCommandHandler() {
        return commandHandler;
    }

    public ComponentHandler getComponentHandler() {
        return componentHandler;
    }

    public UserManager getUserManager() {
        return userManager;
    }

    public ProductManager getProductManager() {
        return productManager;
    }

    public LicenseManager getLicenseManager() {
        return licenseManager;
    }

    public TicketManager getTicketManager() {
        return ticketManager;
    }

    public DownloadManager getDownloadManager() {
        return downloadManager;
    }

    public CryptoManager getCryptoManager() {
        return cryptoManager;
    }

    public TranscriptManager getTranscriptManager() {
        return transcriptManager;
    }

    public DashboardManager getDashboardManager() {
        return dashboardManager;
    }

    public FileHostingService getFileHostingService() {
        return fileHostingService;
    }

    public LogManager getLogManager() {
        return logManager;
    }

    public AuditManager getAuditManager() {
        return auditManager;
    }

    public TicketMessageManager getTicketMessageManager() {
        return ticketMessageManager;
    }
}