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
        // Try to get as int first
        if (!node.node(key).virtual() && node.node(key).raw() instanceof Number) {
            return node.node(key).getInt(0);
        }
        // If it's a string with env var, resolve it
        String value = node.node(key).getString("");
        if (!value.isEmpty()) {
            String resolved = resolveEnvVariables(value);
            try {
                return Integer.parseInt(resolved);
            } catch (NumberFormatException e) {
                return 0;
            }
        }
        return 0;
    }

    @Override
    public boolean readBoolean(String key) {
        // Try to get as boolean first
        if (!node.node(key).virtual() && node.node(key).raw() instanceof Boolean) {
            return node.node(key).getBoolean(false);
        }
        // If it's a string with env var, resolve it
        String value = node.node(key).getString("");
        if (!value.isEmpty()) {
            String resolved = resolveEnvVariables(value);
            return Boolean.parseBoolean(resolved);
        }
        return false;
    }

    @Override
    public long readLong(String key) {
        return node.node(key).getLong(0);
    }

    @Override
    public String readString(String key) {
        String value = node.node(key).getString("");
        return resolveEnvVariables(value);
    }

    /**
     * Resolves environment variables in the format ${ENV_VAR:default}
     * @param value The string potentially containing environment variable references
     * @return The string with environment variables resolved
     */
    private String resolveEnvVariables(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }

        // Pattern: ${ENV_VAR:default} or ${ENV_VAR}
        int startIdx = 0;
        StringBuilder result = new StringBuilder();

        while (startIdx < value.length()) {
            int start = value.indexOf("${", startIdx);
            if (start == -1) {
                // No more variables, append rest of string
                result.append(value.substring(startIdx));
                break;
            }

            int end = value.indexOf("}", start);
            if (end == -1) {
                // Malformed, no closing brace
                result.append(value.substring(startIdx));
                break;
            }

            // Append text before the variable
            result.append(value.substring(startIdx, start));

            // Extract variable expression
            String expr = value.substring(start + 2, end);
            String[] parts = expr.split(":", 2);
            String envName = parts[0];
            String defaultValue = parts.length > 1 ? parts[1] : "";

            // Get environment variable or use default
            String envValue = System.getenv(envName);
            result.append(envValue != null ? envValue : defaultValue);

            startIdx = end + 1;
        }

        return result.toString();
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
