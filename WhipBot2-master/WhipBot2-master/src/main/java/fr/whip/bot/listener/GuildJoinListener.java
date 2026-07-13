package fr.whip.bot.listener;

import fr.whip.bot.WhipBot;
import net.dv8tion.jda.api.events.guild.GuildJoinEvent;

public class GuildJoinListener implements Listener {

    private final WhipBot main;

    public GuildJoinListener(WhipBot main) {
        this.main = main;
    }

    @EventHandler
    public void onGuildJoin(GuildJoinEvent event) {
        main.getCommandHandler().registerCommandsForGuild(event.getGuild());
    }
}
