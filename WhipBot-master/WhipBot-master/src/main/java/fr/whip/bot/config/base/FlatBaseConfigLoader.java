package fr.whip.bot.config.base;

import fr.whip.bot.config.IConfigLoader;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public abstract class FlatBaseConfigLoader<T> implements IConfigLoader<T> {

    protected final Path dataFolder;
    protected final String fileName;
    protected final Path configPath;

    protected FlatBaseConfigLoader(Path dataFolder, String fileName) {
        this.dataFolder = dataFolder;
        this.fileName = fileName;
        this.configPath = dataFolder.resolve(fileName);
    }

    protected abstract void loadFromResources();

    protected abstract void loadFlatConfig();

    protected abstract void loadConfig();

    @Override
    public void load() {
        try {
            Files.createDirectories(dataFolder);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create data folder", e);
        }

        if (!Files.exists(configPath)) {
            loadFromResources();
        }

        loadFlatConfig();
        loadConfig();
    }

    protected void saveResource(String resourceName) {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(resourceName)) {
            if (in == null) {
                return;
            }
            Files.copy(in, configPath);
        } catch (IOException e) {
            throw new RuntimeException("Failed to save resource: " + resourceName, e);
        }
    }
}
