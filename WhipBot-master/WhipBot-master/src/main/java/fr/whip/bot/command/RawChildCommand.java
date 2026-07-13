package fr.whip.bot.command;

import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.build.SubcommandData;

import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

public record RawChildCommand(
        String name,
        String description,
        Consumer<SlashCommandInteractionEvent> eventConsumer,
        Optional<Function<SubcommandData, SubcommandData>> subcommandBuilder)
        implements IChildCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        this.eventConsumer.accept(event);
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getDescription() {
        return this.description;
    }

    @Override
    public SubcommandData build(SubcommandData data) {
        if (subcommandBuilder().isPresent()) {
            return subcommandBuilder.get().apply(data);
        }
        return data;
    }
}
