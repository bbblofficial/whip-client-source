package fr.whip.bot.command;

import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.build.Commands;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

public interface IParentCommand {

    void execute(SlashCommandInteractionEvent event);

    default SlashCommandData build(SlashCommandData data) {
        return data;
    }

    default SlashCommandData toJda() {
        return build(Commands.slash(getName(), getDescription()));
    }

    String getName();

    String getDescription();
}
