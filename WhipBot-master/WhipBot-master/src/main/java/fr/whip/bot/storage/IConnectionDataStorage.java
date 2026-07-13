package fr.whip.bot.storage;

public interface IConnectionDataStorage {

    void connect();

    void close();

    boolean isConnected();
}
