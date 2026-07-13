package fr.whip.bot.command;

import net.dv8tion.jda.api.interactions.commands.build.Commands;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

public interface IParentCommand extends ICommandModel {

    default SlashCommandData build(SlashCommandData data) {
        return data;
    }

    default SlashCommandData toJda() {
        return build(Commands.slash(getName(), getDescription()));
    }
}
