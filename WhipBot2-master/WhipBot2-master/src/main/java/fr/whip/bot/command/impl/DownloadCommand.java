package fr.whip.bot.command.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ChannelsData;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.PermissionsData;
import fr.whip.bot.util.PermissionChecker;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;

public record DownloadCommand(WhipBot main) implements IParentCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        ConfigData config = main.getConfigHandler().getPrototypeConfig(BotConfigLoader.class);
        PermissionsData perms = config.permissions();
        ChannelsData channels = config.channels();

        if (!PermissionChecker.hasRole(event.getMember(), perms.customerRoleId())) {
            event.reply("You don't have permission to use this command.").setEphemeral(true).queue();
            return;
        }
        if (!PermissionChecker.inChannel(event.getChannel(), channels.downloadCustomerChannelId())) {
            event.reply("This command can only be used in the customer download channel.").setEphemeral(true).queue();
            return;
        }

        // TODO: implementation
        event.reply("⏳ Coming soon.").setEphemeral(true).queue();
    }

    @Override
    public String getName() {
        return "download";
    }

    @Override
    public String getDescription() {
        return "Download the Whip loader";
    }
}
