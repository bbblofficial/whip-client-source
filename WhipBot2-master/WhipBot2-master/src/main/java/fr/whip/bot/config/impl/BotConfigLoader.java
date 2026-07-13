package fr.whip.bot.config.impl;

import fr.whip.bot.config.base.ConfigurateBaseConfigLoader;
import fr.whip.bot.data.ChannelsData;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.DatabaseData;
import fr.whip.bot.data.FileHostingData;
import fr.whip.bot.data.PermissionsData;
import org.spongepowered.configurate.serialize.SerializationException;

import java.io.File;
import java.nio.file.Path;

public class BotConfigLoader extends ConfigurateBaseConfigLoader<ConfigData> {

    private ConfigData config;

    public BotConfigLoader(Path dataFolder) {
        super(dataFolder, "config");
    }

    @Override
    protected void loadConfig() {
        this.config = new ConfigData(
                env("DISCORD_BOT_TOKEN", dataReader.readString("token")),
                loadFromConfig("database", (id, reader) -> new DatabaseData(
                        env("DB_HOST", reader.readString("host")),
                        envInt("DB_PORT", reader.readInt("port")),
                        env("DB_NAME", reader.readString("database")),
                        env("DB_USER", reader.readString("username")),
                        env("DB_PASSWORD", reader.readString("password")))),
                resolveLoader(env("LOADER_PATH", dataReader.readString("loader-path"))),
                loadFromConfig("file-hosting", (id, reader) -> new FileHostingData(
                        envBool("FILE_HOSTING_ENABLED", reader.readBoolean("enabled")),
                        envInt("FILE_HOSTING_PORT", reader.readInt("port")),
                        env("FILE_HOSTING_BASE_URL", reader.readString("base-url")))),
                loadFromConfig("channels", (id, reader) -> new ChannelsData(
                        env("GUILD_ID", reader.readString("guild-id")),
                        env("CUSTOMER_GUILD_ID", reader.readString("customer-guild-id")),
                        reader.readString("ticket-category-id"),
                        reader.readString("buy-ticket-category-id"),
                        reader.readString("questions-ticket-category-id"),
                        reader.readString("hwid-ticket-category-id"),
                        reader.readString("other-ticket-category-id"),
                        reader.readString("suggestion-channel-id"),
                        reader.readString("bug-report-channel-id"),
                        reader.readString("download-channel-id"),
                        reader.readString("transcript-logs-channel-id"),
                        reader.readString("download-customer-channel-id"),
                        reader.readString("download-beta-channel-id"),
                        reader.readString("suggestion-customer-channel-id"),
                        reader.readString("suggestion-beta-channel-id"),
                        reader.readString("bug-report-customer-channel-id"),
                        reader.readString("bug-report-beta-channel-id"))),
                loadFromConfig("permissions", (id, reader) -> new PermissionsData(
                        reader.readString("singerie-user-id"),
                        parseIds(reader.readString("owner-role-ids")),
                        reader.readString("support-role-id"),
                        reader.readString("customer-role-id"),
                        reader.readString("beta-role-id"))),
                env("OPENAI_API_KEY", dataReader.readString("openai-api-key")),
                dataReader.readString("translation-prompt"),
                dataReader.readString("language-detection-prompt"));
    }

    private File resolveLoader(String path) {
        Path p = Path.of(path);
        return p.isAbsolute() ? p.toFile() : dataFolder.resolve(p).toFile();
    }

    private static java.util.List<String> parseIds(String raw) {
        if (raw == null || raw.isBlank()) return java.util.List.of();
        return java.util.Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    private static String env(String key, String fallback) {
        String value = System.getenv(key);
        return value != null && !value.isEmpty() ? value : fallback;
    }

    private static int envInt(String key, int fallback) {
        String value = System.getenv(key);
        if (value != null && !value.isEmpty()) {
            try { return Integer.parseInt(value); } catch (NumberFormatException ignored) {}
        }
        return fallback;
    }

    private static boolean envBool(String key, boolean fallback) {
        String value = System.getenv(key);
        return value != null && !value.isEmpty() ? Boolean.parseBoolean(value) : fallback;
    }

    @Override
    public ConfigData get() {
        return config;
    }

    public void updateDownloadChannelId(String newId) {
        try {
            rootNode.node("channels", "download-channel-id").set(newId);
            loadConfig();
            save();
        } catch (SerializationException e) {
            throw new RuntimeException("Failed to update download channel ID", e);
        }
    }

    public void updateSuggestionChannelId(String newId) {
        try {
            rootNode.node("channels", "suggestion-channel-id").set(newId);
            loadConfig();
            save();
        } catch (SerializationException e) {
            throw new RuntimeException("Failed to update suggestion channel ID", e);
        }
    }

    public void updateBugReportChannelId(String newId) {
        try {
            rootNode.node("channels", "bug-report-channel-id").set(newId);
            loadConfig();
            save();
        } catch (SerializationException e) {
            throw new RuntimeException("Failed to update bug report channel ID", e);
        }
    }

    public org.spongepowered.configurate.ConfigurationNode getRootNode() {
        return rootNode;
    }

    public void reload() {
        loadFlatConfig();
        loadConfig();
    }

    public void updateTranscriptLogsChannelId(String newId) {
        try {
            rootNode.node("channels", "transcript-logs-channel-id").set(newId);
            loadConfig();
            save();
        } catch (SerializationException e) {
            throw new RuntimeException("Failed to update transcript logs channel ID", e);
        }
    }
}