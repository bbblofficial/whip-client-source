package fr.whip.bot.util;

import net.dv8tion.jda.api.interactions.commands.CommandInteractionPayload;
import net.dv8tion.jda.api.interactions.commands.OptionMapping;

import java.util.Optional;

public class OptionUtils {

    public static Optional<String> getStringOption(CommandInteractionPayload event, String name) {
        OptionMapping option = event.getOption(name);
        if (option != null) {
            return Optional.of(option.getAsString());
        }
        return Optional.empty();
    }

    public static Optional<Integer> getIntOption(CommandInteractionPayload event, String name) {
        OptionMapping option = event.getOption(name);
        if (option != null) {
            return Optional.of(option.getAsInt());
        }
        return Optional.empty();
    }

    public static Optional<Long> getLongOption(CommandInteractionPayload event, String name) {
        OptionMapping option = event.getOption(name);
        if (option != null) {
            return Optional.of(option.getAsLong());
        }
        return Optional.empty();
    }

    public static Optional<Boolean> getBooleanOption(CommandInteractionPayload event, String name) {
        OptionMapping option = event.getOption(name);
        if (option != null) {
            return Optional.of(option.getAsBoolean());
        }
        return Optional.empty();
    }

    public static Optional<Double> getDoubleOption(CommandInteractionPayload event, String name) {
        OptionMapping option = event.getOption(name);
        if (option != null) {
            return Optional.of(option.getAsDouble());
        }

        return Optional.empty();
    }
}