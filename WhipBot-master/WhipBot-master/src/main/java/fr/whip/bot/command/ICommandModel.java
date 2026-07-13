package fr.whip.bot.command;

import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;

public interface ICommandModel {

    void execute(SlashCommandInteractionEvent event);

    String getName();

    String getDescription();
}
