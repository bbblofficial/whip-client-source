package fr.whip.bot;

import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.handler.*;
import fr.whip.bot.listener.CommandListener;
import fr.whip.bot.listener.ComponentListener;
import fr.whip.bot.manager.impl.*;
import fr.whip.bot.service.FileHostingService;
import fr.whip.bot.storage.hibernate.HibernateConnection;
import fr.whip.bot.storage.sync.SyncListener;
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
    private ModuleHandler moduleHandler;
    private ListenerHandler listenerHandler;
    private CommandHandler commandHandler;
    private ComponentHandler componentHandler;

    private UserManager userManager;
    private ProductManager productManager;
    private LicenseManager licenseManager;
    private MachineManager machineManager;
    private DownloadManager downloadManager;
    private SyncListener syncListener;
    private FileHostingService fileHostingService;

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

        this.userManager = new UserManager(hibernate);
        this.productManager = new ProductManager(hibernate);
        this.licenseManager = new LicenseManager(hibernate);
        this.machineManager = new MachineManager(hibernate);
        this.downloadManager = new DownloadManager(hibernate);

        this.userManager.start();
        this.productManager.start();
        this.licenseManager.start();
        this.machineManager.start();
        this.downloadManager.start();

        this.syncListener = new SyncListener(
                config.database(),
                userManager, productManager, licenseManager, machineManager, downloadManager
        );
        this.syncListener.start();

        if (config.fileHosting().enabled()) {
            this.fileHostingService = new FileHostingService(
                    config.fileHosting().port(),
                    config.fileHosting().baseUrl()
            );
            this.fileHostingService.start();
            LOGGER.info("File hosting service started on port {}", config.fileHosting().port());
        }

        try {
            this.jda = JDABuilder.createDefault(config.token())
                    .enableIntents(GatewayIntent.GUILD_MEMBERS, GatewayIntent.MESSAGE_CONTENT)
                    .build()
                    .awaitReady();
        } catch (InterruptedException e) {
            LOGGER.error("Failed to initialize JDA", e);
            Thread.currentThread().interrupt();
            return;
        }

        LOGGER.info("JDA connected successfully");

        this.listenerHandler = new ListenerHandler();
        this.listenerHandler.init(this);

        this.componentHandler = new ComponentHandler();

        this.commandHandler = new CommandHandler();

        this.moduleHandler = new ModuleHandler();
        this.moduleHandler.init();
        this.moduleHandler.load(this);

        this.listenerHandler.register(new CommandListener(this));
        this.listenerHandler.register(new ComponentListener(this));

        this.commandHandler.init(this);

        this.running = true;
        LOGGER.info("WhipBot enabled successfully!");
    }

    public void onDisable() {
        LOGGER.info("Disabling WhipBot...");

        if (fileHostingService != null) {
            fileHostingService.stop();
        }

        if (syncListener != null) {
            syncListener.stop();
        }

        if (moduleHandler != null) {
            moduleHandler.unload(this);
        }

        if (jda != null) {
            jda.shutdown();
        }

        if (userManager != null) userManager.stop();
        if (productManager != null) productManager.stop();
        if (licenseManager != null) licenseManager.stop();
        if (machineManager != null) machineManager.stop();

        if (connectionHandler != null) {
            connectionHandler.stop();
        }

        if (configHandler != null) {
            configHandler.clear();
        }

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

    public ModuleHandler getModuleHandler() {
        return moduleHandler;
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

    public MachineManager getMachineManager() {
        return machineManager;
    }

    public DownloadManager getDownloadManager() {
        return downloadManager;
    }

    public FileHostingService getFileHostingService() {
        return fileHostingService;
    }
}