package fr.whip.bot.data;

import java.io.File;

public record ConfigData(
        String token,
        DatabaseData database,
        File loaderPath,
        FileHostingData fileHosting
) {

    public ConfigData {
        if (database == null) {
            database = new DatabaseData("localhost", 5432, "whip", "whip", "");
        }
        if (fileHosting == null) {
            fileHosting = new FileHostingData(true, 8080, "http://localhost:8080");
        }
    }
}