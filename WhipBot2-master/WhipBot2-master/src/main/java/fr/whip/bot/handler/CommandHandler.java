package fr.whip.bot.handler;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.command.impl.*;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import net.dv8tion.jda.api.interactions.IntegrationType;
import net.dv8tion.jda.api.interactions.InteractionContextType;

import java.util.HashMap;
import java.util.Map;

public class CommandHandler {

    private final Map<String, IParentCommand> commands;

    public CommandHandler() {
        this.commands = new HashMap<>();
    }

    public void init(WhipBot main) {
        ConfigData config = main.getConfigHandler().getPrototypeConfig(BotConfigLoader.class);







        register(new RegisterCommand(main));
        register(new ClearCommand(main));
        register(new LicenseCommand(main));
        register(new PurgeCommand(main));
        register(new SetupPanelCommand(main));
        register(new SetupCommand(main));
        register(new DetectCommand(main));
        register(new TicketHelpCommand());
        register(new DashboardCommand(main));

        register(new CreateTicketCommand(main.getTicketManager(), config, main.getJda()));
        register(new CloseTicketCommand(main.getTicketManager()));
        register(new WaitCommand(main));
        register(new TicketBanCommand(main));
        register(new TicketUnbanCommand(main));

        register(new SuggestionCommand(main));
        register(new ReportCommand(main));

        register(new DownloadCommand(main));
        register(new BetaDownloadCommand(main));

        main.getJda().updateCommands()
                .addCommands(
                        new RegisterCommand(main).toJda()
                                .setIntegrationTypes(IntegrationType.GUILD_INSTALL)
                                .setContexts(InteractionContextType.GUILD, InteractionContextType.BOT_DM),
                        new CloseTicketCommand(main.getTicketManager()).toJda()
                                .setIntegrationTypes(IntegrationType.GUILD_INSTALL)
                                .setContexts(InteractionContextType.GUILD, InteractionContextType.BOT_DM),
                        new TicketHelpCommand().toJda()
                                .setIntegrationTypes(IntegrationType.GUILD_INSTALL)
                                .setContexts(InteractionContextType.GUILD, InteractionContextType.BOT_DM))
                .queue();

        for (net.dv8tion.jda.api.entities.Guild guild : main.getJda().getGuilds()) {
            registerCommandsForGuild(guild);
        }
    }

    public void registerCommandsForGuild(net.dv8tion.jda.api.entities.Guild guild) {
        guild.updateCommands()
                .addCommands(commands.values().stream().map(IParentCommand::toJda).toList())
                .queue(v -> System.out.println("Commands registered on guild " + guild.getName() + " (" + commands.size() + ")"),
                        err -> System.err.println("Failed to register commands on guild " + guild.getName() + ": " + err.getMessage()));
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