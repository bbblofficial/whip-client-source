package fr.whip.bot.command.base;

import fr.whip.bot.command.IChildCommand;
import fr.whip.bot.command.IParentComplexCommand;
import fr.whip.bot.command.RawChildCommand;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.build.SubcommandData;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

public abstract class ParentComplexBaseCommand implements IParentComplexCommand {

    protected final Map<String, IChildCommand> childCommands;

    public ParentComplexBaseCommand() {
        this.childCommands = new HashMap<>();
    }

    public void registerChildCommand(IChildCommand childCommand) {
        this.childCommands.put(childCommand.getName(), childCommand);
    }

    public void registerChildCommand(
            String name,
            String description,
            Consumer<SlashCommandInteractionEvent> eventConsumer,
            Optional<Function<SubcommandData, SubcommandData>> subcommandBuilder) {
        registerChildCommand(new RawChildCommand(name, description, eventConsumer, subcommandBuilder));
    }

    @Override
    public Map<String, IChildCommand> getChildCommands() {
        return this.childCommands;
    }
}
