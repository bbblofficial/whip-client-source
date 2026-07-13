package fr.whip.bot.command;

import net.dv8tion.jda.api.interactions.commands.build.SubcommandData;

public interface IChildCommand extends ICommandModel {

    default SubcommandData build(SubcommandData data) {
        return data;
    }

    default SubcommandData toJda() {
        return build(new SubcommandData(getName(), getDescription()));
    }
}
