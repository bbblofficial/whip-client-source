package fr.whip.bot.command.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

public record HWIDResetCommand(WhipBot main) implements IParentCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        event.reply("This feature is currently disabled.").setEphemeral(true).queue();
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data;
    }

    @Override
    public String getName() {
        return "hwidreset_disabled";
    }

    @Override
    public String getDescription() {
        return "Disabled feature";
    }
}
