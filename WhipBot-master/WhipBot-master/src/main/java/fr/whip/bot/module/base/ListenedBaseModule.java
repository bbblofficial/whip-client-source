package fr.whip.bot.module.base;

import fr.whip.bot.WhipBot;
import fr.whip.bot.listener.Listener;
import fr.whip.bot.module.ModuleType;

public abstract class ListenedBaseModule extends BaseModule implements Listener {

    public ListenedBaseModule(ModuleType type) {
        super(type);
    }

    @Override
    public void onLoad(WhipBot main) {
        super.onLoad(main);
        main.getListenerHandler().register(this);
    }

    @Override
    public void onUnload(WhipBot main) {
        main.getListenerHandler().unregister(this);
        super.onUnload(main);
    }
}
