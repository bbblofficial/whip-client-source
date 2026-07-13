package fr.whip.bot.command;

import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.build.Commands;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;
import net.dv8tion.jda.api.interactions.commands.build.SubcommandData;

import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

public interface IParentComplexCommand extends IParentCommand {

    Map<String, IChildCommand> getChildCommands();

    void registerChildCommand(IChildCommand childCommand);

    void registerChildCommand(
            String name,
            String description,
            Consumer<SlashCommandInteractionEvent> eventConsumer,
            Optional<Function<SubcommandData, SubcommandData>> subcommandBuilder);

    default void registerChildCommand(
            String name, String description, Consumer<SlashCommandInteractionEvent> eventConsumer) {
        registerChildCommand(name, description, eventConsumer, Optional.empty());
    }

    default boolean hasSubcommand(String subcommand) {
        return getChildCommands().containsKey(subcommand);
    }

    @Override
    default void execute(SlashCommandInteractionEvent event) {
        if (event.getSubcommandName() == null
                || !getChildCommands().containsKey(event.getSubcommandName())) {
            event.reply("Sub command not found!").setEphemeral(true).queue();
            return;
        }

        getChildCommands().get(event.getSubcommandName()).execute(event);
    }

    @Override
    default SlashCommandData toJda() {
        return build(Commands.slash(getName(), getDescription()))
                .addSubcommands(getChildCommands().values().stream().map(IChildCommand::toJda).toList());
    }
}
