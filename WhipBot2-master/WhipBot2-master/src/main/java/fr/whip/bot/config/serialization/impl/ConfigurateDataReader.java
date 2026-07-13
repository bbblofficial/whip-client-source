package fr.whip.bot.config.serialization.impl;

import fr.whip.bot.config.serialization.IDataReader;
import org.spongepowered.configurate.ConfigurationNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public record ConfigurateDataReader(ConfigurationNode node) implements IDataReader {

    public static ConfigurateDataReader from(ConfigurationNode node) {
        return new ConfigurateDataReader(node);
    }

    @Override
    public int readInt(String key) {
        return node.node(key).getInt(0);
    }

    @Override
    public boolean readBoolean(String key) {
        return node.node(key).getBoolean(false);
    }

    @Override
    public long readLong(String key) {
        return node.node(key).getLong(0);
    }

    @Override
    public String readString(String key) {
        return node.node(key).getString("");
    }

    @Override
    public float readFloat(String key) {
        return node.node(key).getFloat(0f);
    }

    @Override
    public double readDouble(String key) {
        return node.node(key).getDouble(0d);
    }

    @Override
    public boolean has(String key) {
        return !node.node(key).virtual();
    }

    @Override
    public Set<String> getKeys() {
        if (node.isMap()) {
            Set<String> keys = new HashSet<>();
            for (Object key : node.childrenMap().keySet()) {
                keys.add(key.toString());
            }
            return keys;
        }
        return Collections.emptySet();
    }

    @Override
    public IDataReader getSection(String key) {
        ConfigurationNode child = node.node(key);
        return child.virtual() ? null : new ConfigurateDataReader(child);
    }

    @Override
    public List<String> readStringList(String key) {
        try {
            List<String> list = node.node(key).getList(String.class);
            return list != null ? list : Collections.emptyList();
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    @Override
    public List<IDataReader> getSectionList(String key) {
        ConfigurationNode listNode = node.node(key);
        if (listNode.virtual() || !listNode.isMap()) {
            return Collections.emptyList();
        }

        List<IDataReader> readers = new ArrayList<>();
        for (ConfigurationNode child : listNode.childrenMap().values()) {
            readers.add(new ConfigurateDataReader(child));
        }
        return readers;
    }
}
