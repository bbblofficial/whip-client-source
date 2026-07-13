package fr.whip.bot.command;

import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

public record RawParentCommand(
        String name,
        String description,
        Consumer<SlashCommandInteractionEvent> eventConsumer,
        Optional<Function<SlashCommandData, SlashCommandData>> commandBuilder)
        implements IParentCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        eventConsumer.accept(event);
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
    public SlashCommandData build(SlashCommandData data) {
        if (commandBuilder.isPresent()) {
            return commandBuilder.get().apply(data);
        }
        return data;
    }
}
