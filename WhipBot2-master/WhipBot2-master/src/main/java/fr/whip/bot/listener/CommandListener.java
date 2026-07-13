package fr.whip.bot.listener;

import fr.whip.bot.WhipBot;
import fr.whip.bot.data.log.LogCategory;
import fr.whip.bot.data.log.LogLevel;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;

public class CommandListener implements Listener {

    private final WhipBot main;

    public CommandListener(WhipBot main) {
        this.main = main;
    }

    @EventHandler
    public void onCommand(SlashCommandInteractionEvent event) {
        if (!this.main.getCommandHandler().hasCommand(event.getName())) {
            event.reply("Command not found!").setEphemeral(true).queue();
            return;
        }

        main.getLogManager().log(LogLevel.INFO, LogCategory.COMMAND, event.getUser().getId(),
                "/" + event.getName() + (event.getSubcommandName() != null ? " " + event.getSubcommandName() : ""));
        this.main.getCommandHandler().getCommand(event.getName()).execute(event);
    }

    public WhipBot getMain() {
        return main;
    }
}
