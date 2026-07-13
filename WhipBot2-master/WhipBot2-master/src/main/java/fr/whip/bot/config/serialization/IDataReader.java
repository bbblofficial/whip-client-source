package fr.whip.bot.config.serialization;

import java.util.List;
import java.util.Set;

public interface IDataReader {

    int readInt(String key);

    boolean readBoolean(String key);

    long readLong(String key);

    String readString(String key);

    float readFloat(String key);

    double readDouble(String key);

    boolean has(String key);

    Set<String> getKeys();

    IDataReader getSection(String key);

    List<String> readStringList(String key);

    List<IDataReader> getSectionList(String key);
}
