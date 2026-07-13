package fr.whip.bot.command.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.PermissionsData;
import fr.whip.bot.util.PermissionChecker;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.DefaultMemberPermissions;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

public record ClearCommand(WhipBot main) implements IParentCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        if (!(event.getChannel() instanceof TextChannel textChannel)) {
            event.reply("This command can only be used in text channels.").setEphemeral(true).queue();
            return;
        }

        ConfigData config = main.getConfigHandler().getPrototypeConfig(BotConfigLoader.class);
        PermissionsData perms = config.permissions();
        if (!PermissionChecker.isUser(event.getUser(), perms.singerieUserId())) {
            event.reply("You don't have permission to use this command.").setEphemeral(true).queue();
            return;
        }
        String oldId = textChannel.getId();

        boolean isDownloadChannel = oldId.equals(config.channels().downloadChannelId());
        boolean isSuggestionChannel = oldId.equals(config.channels().suggestionChannelId());
        boolean isBugReportChannel = oldId.equals(config.channels().bugReportChannelId());

        event.reply("Clearing channel...").setEphemeral(true).queue(hook -> {
            textChannel.createCopy().setPosition(textChannel.getPosition()).queue(newChannel -> {
                textChannel.delete().queue();
                newChannel.sendMessage(
                        "https://tenor.com/view/nuke-automic-boom-boom-nuked-gif-19961792")
                        .queue();

                if (isDownloadChannel) {
                    main.getConfigHandler().getConfig(BotConfigLoader.class)
                            .updateDownloadChannelId(newChannel.getId());
                } else if (isSuggestionChannel) {
                    main.getConfigHandler().getConfig(BotConfigLoader.class)
                            .updateSuggestionChannelId(newChannel.getId());
                } else if (isBugReportChannel) {
                    main.getConfigHandler().getConfig(BotConfigLoader.class)
                            .updateBugReportChannelId(newChannel.getId());
                }
            });
        });
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data.setDefaultPermissions(DefaultMemberPermissions.enabledFor(Permission.MANAGE_CHANNEL));
    }

    @Override
    public String getName() {
        return "clear";
    }

    @Override
    public String getDescription() {
        return "Clears the current channel by recreating it";
    }
}
