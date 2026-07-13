package fr.whip.bot.handler;

import fr.whip.bot.storage.IConnectionDataStorage;

import java.util.HashMap;
import java.util.Map;

public class ConnectionHandler {

    private final Map<Class<? extends IConnectionDataStorage>, IConnectionDataStorage> connections;

    public ConnectionHandler(int initialCapacity) {
        this.connections = new HashMap<>(initialCapacity);
    }

    public void init(IConnectionDataStorage... connections) {
        for (IConnectionDataStorage connection : connections) {
            connection.connect();
            this.connections.put(connection.getClass(), connection);
        }
    }

    public synchronized void stop() {
        for (IConnectionDataStorage connection : this.connections.values()) {
            connection.close();
        }
        this.connections.clear();
    }

    @SuppressWarnings("unchecked")
    public synchronized <T extends IConnectionDataStorage> T get(Class<T> clazz) {
        IConnectionDataStorage storage = this.connections.get(clazz);
        if (storage == null) {
            throw new IllegalStateException("Connection not found for class: " + clazz.getName());
        }
        return (T) storage;
    }
}
