package fr.whip.bot.data;

public record DatabaseData(String host, int port, String database, String username, String password) {

    public DatabaseData {
        if (host == null || host.isEmpty()) host = "localhost";
        if (port <= 0) port = 5432;
        if (database == null || database.isEmpty()) database = "whip";
        if (username == null || username.isEmpty()) username = "whip";
        if (password == null) password = "";
    }
}