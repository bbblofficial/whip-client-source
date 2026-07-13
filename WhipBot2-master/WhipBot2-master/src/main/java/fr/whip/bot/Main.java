package fr.whip.bot;

import java.nio.file.Path;

public class Main {

    public static void main(String[] args) {
        Path dataFolder = Path.of(".");

        WhipBot whipBot = new WhipBot(dataFolder);
        whipBot.onEnable();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (whipBot.isRunning()) {
                whipBot.onDisable();
            }
        }, "WhipBot Shutdown"));
    }
}
