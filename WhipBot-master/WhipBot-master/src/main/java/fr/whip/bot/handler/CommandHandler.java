package fr.whip.bot.handler;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.command.impl.DownloadCommand;
import fr.whip.bot.command.impl.LicenseCommand;
import fr.whip.bot.command.impl.ProductCommand;
import fr.whip.bot.command.impl.RegisterCommand;
import fr.whip.bot.config.impl.BotConfigLoader;

import java.util.HashMap;
import java.util.Map;

public class CommandHandler {
    private final Map<String, IParentCommand> commands;

    public CommandHandler() {
        this.commands = new HashMap<>();
    }

    public void init(WhipBot main) {
        register(new RegisterCommand(main.getUserManager(), main.getLicenseManager()));
        register(new DownloadCommand(
                main.getUserManager(),
                main.getLicenseManager(),
                main.getDownloadManager(),
                main.getConfigHandler().getPrototypeConfig(BotConfigLoader.class),
                main.getFileHostingService()
        ));
        register(new LicenseCommand(main.getLicenseManager(), main.getProductManager(), main.getUserManager()));
        register(new ProductCommand(main.getProductManager()));

        main.getJda()
                .updateCommands()
                .addCommands(commands.values().stream().map(IParentCommand::toJda).toList())
                .queue();
    }

    public void register(IParentCommand command) {
        this.commands.put(command.getName(), command);
    }

    public boolean hasCommand(String commandName) {
        return this.commands.containsKey(commandName);
    }

    public IParentCommand getCommand(String commandName) {
        return this.commands.get(commandName);
    }
}