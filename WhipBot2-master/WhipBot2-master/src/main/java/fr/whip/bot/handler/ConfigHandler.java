package fr.whip.bot.handler;

import fr.whip.bot.config.IConfigLoader;
import fr.whip.bot.config.impl.BotConfigLoader;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public class ConfigHandler {

    private final Map<Class<?>, IConfigLoader<?>> configs;

    public ConfigHandler() {
        this.configs = new HashMap<>(1);
    }

    public void init(Path dataFolder) {
        addConfig(new BotConfigLoader(dataFolder));
    }

    public void load() {
        for (IConfigLoader<?> config : this.configs.values()) {
            config.load();
        }
    }

    public void clear() {
        this.configs.clear();
    }

    public void addConfig(IConfigLoader<?> config) {
        this.configs.put(config.getClass(), config);
    }

    @SuppressWarnings("unchecked")
    public <T> T getPrototypeConfig(Class<?> type) {
        return (T) this.configs.get(type).get();
    }

    @SuppressWarnings("unchecked")
    public <T extends IConfigLoader<?>> T getConfig(Class<T> type) {
        return (T) this.configs.get(type);
    }
}