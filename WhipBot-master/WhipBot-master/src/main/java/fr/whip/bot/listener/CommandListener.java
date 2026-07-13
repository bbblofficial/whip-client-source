package fr.whip.bot.listener;

import fr.whip.bot.WhipBot;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;

public record CommandListener(WhipBot main) implements Listener {

    @EventHandler
    public void onCommand(SlashCommandInteractionEvent event) {
        if (!this.main.getCommandHandler().hasCommand(event.getName())) {
            event.reply("Command not found!").setEphemeral(true).queue();
            return;
        }

        this.main.getCommandHandler().getCommand(event.getName()).execute(event);
    }
}
