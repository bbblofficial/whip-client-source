package fr.whip.bot.module.base;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.command.IParentComplexCommand;
import fr.whip.bot.command.RawParentCommand;
import fr.whip.bot.command.RawParentComplexCommand;
import fr.whip.bot.module.IModule;
import fr.whip.bot.module.ModuleType;
import net.dv8tion.jda.api.JDA;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

public abstract class BaseModule implements IModule {

    private static final Logger LOGGER = LoggerFactory.getLogger(BaseModule.class);

    protected final ModuleType type;
    protected boolean enable;

    public BaseModule(ModuleType type) {
        this.type = type;
    }

    @Override
    public void onLoad(WhipBot main) {
        this.enable = true;
        LOGGER.info("Module {} has been loaded.", this.getId());
    }

    @Override
    public void onUnload(WhipBot main) {
        this.enable = false;
        LOGGER.info("Module {} has been unloaded.", this.getId());
    }

    protected JDA getJda(WhipBot main) {
        return main.getJda();
    }

    protected void registerSimpleCommand(
            WhipBot main,
            String name,
            String description,
            Consumer<SlashCommandInteractionEvent> eventConsumer,
            Optional<Function<SlashCommandData, SlashCommandData>> commandBuilder) {
        registerCommand(main, new RawParentCommand(name, description, eventConsumer, commandBuilder));
    }

    protected IParentComplexCommand registerParentCommand(
            WhipBot main,
            String name,
            String description,
            Optional<Function<SlashCommandData, SlashCommandData>> commandBuilder) {
        RawParentComplexCommand complexCommand =
                new RawParentComplexCommand(name, description, commandBuilder);
        registerCommand(main, complexCommand);
        return complexCommand;
    }

    protected IParentComplexCommand registerParentCommand(WhipBot main, String name, String description) {
        return registerParentCommand(main, name, description, Optional.empty());
    }

    protected void registerCommand(WhipBot main, IParentCommand parentCommand) {
        main.getCommandHandler().register(parentCommand);
    }

    @Override
    public ModuleType getType() {
        return this.type;
    }

    @Override
    public boolean isEnable() {
        return this.enable;
    }
}
