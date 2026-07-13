package fr.whip.bot.module;

import fr.whip.bot.WhipBot;

public interface IModule {

    void onLoad(WhipBot main);

    void onUnload(WhipBot main);

    boolean isEnable();

    default String getId() {
        return getType().name().replace("_", "").toLowerCase();
    }

    ModuleType getType();
}
