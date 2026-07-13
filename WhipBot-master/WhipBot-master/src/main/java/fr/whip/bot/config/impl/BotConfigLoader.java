package fr.whip.bot.config.impl;

import fr.whip.bot.config.base.ConfigurateBaseConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.DatabaseData;
import fr.whip.bot.data.FileHostingData;

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
                dataReader.readString("token"),
                loadFromConfig("database", (id, reader) -> new DatabaseData(
                        reader.readString("host"),
                        reader.readInt("port"),
                        reader.readString("database"),
                        reader.readString("username"),
                        reader.readString("password")
                )),
                new File(dataReader.readString("loader-path")),
                loadFromConfig("file-hosting", (id, reader) -> new FileHostingData(
                        reader.readBoolean("enabled"),
                        reader.readInt("port"),
                        reader.readString("base-url")
                ))
        );
    }

    @Override
    public ConfigData get() {
        return config;
    }
}