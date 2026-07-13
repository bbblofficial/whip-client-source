package fr.whip.bot.config;

import java.util.function.Function;

public interface IConfigLoader<T> {

    Function<String, String> PARSE_ENUM = section -> section.toUpperCase().replace("-", "_");

    void load();

    T get();
}
