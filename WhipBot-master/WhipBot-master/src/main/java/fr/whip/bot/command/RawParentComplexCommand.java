package fr.whip.bot.command;

import fr.whip.bot.command.base.ParentComplexBaseCommand;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

import java.util.Optional;
import java.util.function.Function;

public class RawParentComplexCommand extends ParentComplexBaseCommand {

    private final String name;
    private final String description;
    private final Optional<Function<SlashCommandData, SlashCommandData>> optionalCommandData;

    public RawParentComplexCommand(
            String name,
            String description,
            Optional<Function<SlashCommandData, SlashCommandData>> optionalCommandData) {
        this.name = name;
        this.description = description;
        this.optionalCommandData = optionalCommandData;
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
        if (optionalCommandData.isPresent()) {
            return optionalCommandData.get().apply(data);
        }
        return data;
    }
}
