package fr.whip.bot.config.base;

import fr.whip.bot.config.serialization.IDataReader;
import fr.whip.bot.config.serialization.impl.ConfigurateDataReader;
import org.spongepowered.configurate.ConfigurationNode;
import org.spongepowered.configurate.yaml.YamlConfigurationLoader;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

public abstract class ConfigurateBaseConfigLoader<T> extends FlatBaseConfigLoader<T> {

    protected ConfigurateDataReader dataReader;
    protected ConfigurationNode rootNode;

    public ConfigurateBaseConfigLoader(Path dataFolder, String configName) {
        super(dataFolder, configName + ".yml");
    }

    @Override
    protected void loadFlatConfig() {
        try {
            YamlConfigurationLoader loader = YamlConfigurationLoader.builder()
                    .path(configPath)
                    .build();
            this.rootNode = loader.load();
            this.dataReader = ConfigurateDataReader.from(rootNode);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load config: " + fileName, e);
        }
    }

    @Override
    protected void loadFromResources() {
        saveResource(fileName);
    }

    protected <V> Map<String, V> loadFromConfigSection(
            String sectionId, BiFunction<String, IDataReader, V> mapper) {
        IDataReader section = this.dataReader.getSection(sectionId);
        if (section == null) return Collections.emptyMap();

        return loadFromConfigSection(section, mapper);
    }

    protected <K, V> Map<K, V> loadFromConfigSingleSection(
            String sectionId,
            BiFunction<String, IDataReader, V> mapper,
            Function<String, K> parser) {
        IDataReader section = this.dataReader.getSection(sectionId);
        if (section == null) return Collections.emptyMap();

        Set<String> keys = section.getKeys();
        Map<K, V> result = new HashMap<>(keys.size());
        for (String key : keys) {
            IDataReader subSection = section.getSection(key);
            if (subSection == null) {
                continue;
            }
            result.put(parser.apply(key), mapper.apply(key, subSection));
        }

        return result;
    }

    protected <V> Map<String, V> loadFromConfigSection(
            String sectionId,
            IDataReader parentSection,
            BiFunction<String, IDataReader, V> mapper) {
        IDataReader section = parentSection.getSection(sectionId);
        if (section == null) return Collections.emptyMap();

        return loadFromConfigSection(section, mapper);
    }

    protected <V> Map<String, V> loadFromConfigSection(
            IDataReader section, BiFunction<String, IDataReader, V> mapper) {
        Set<String> keys = section.getKeys();
        Map<String, V> result = new HashMap<>(keys.size());
        for (String key : keys) {
            IDataReader subSection = section.getSection(key);

            if (subSection != null) {
                V value = mapper.apply(key, subSection);
                if (value != null) {
                    result.put(key, value);
                }
            }
        }
        return result;
    }

    protected <E extends Enum<E>> EnumSet<E> loadEnumSetFromConfig(
            IDataReader section, String key, Class<E> enumClass) {
        List<String> enumNames = section.readStringList(key);
        if (enumNames.isEmpty()) {
            return EnumSet.noneOf(enumClass);
        }

        EnumSet<E> enumSet = EnumSet.noneOf(enumClass);
        for (String enumName : enumNames) {
            try {
                enumSet.add(Enum.valueOf(enumClass, enumName.toUpperCase()));
            } catch (IllegalArgumentException e) {
                System.err.println("Invalid " + enumClass.getSimpleName() + ": " + enumName);
            }
        }
        return enumSet;
    }

    protected <V> V loadFromConfig(
            String sectionId,
            BiFunction<String, IDataReader, V> mapper) {
        IDataReader section = this.dataReader.getSection(sectionId);
        if (section == null) return null;

        return mapper.apply(sectionId, section);
    }

    protected <V> V loadFromConfig(
            String sectionId,
            IDataReader parentSection,
            BiFunction<String, IDataReader, V> mapper) {
        IDataReader section = parentSection.getSection(sectionId);
        if (section == null) return null;

        return mapper.apply(sectionId, section);
    }
}
