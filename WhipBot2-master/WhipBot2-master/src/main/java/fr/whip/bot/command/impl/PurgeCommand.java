package fr.whip.bot.command.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.entities.channel.middleman.MessageChannel;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.DefaultMemberPermissions;
import net.dv8tion.jda.api.interactions.commands.OptionMapping;
import net.dv8tion.jda.api.interactions.commands.OptionType;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

import java.util.concurrent.TimeUnit;

public record PurgeCommand(WhipBot main) implements IParentCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        if (!event.isFromGuild()) {
            event.reply("This command can only be used in a server.").setEphemeral(true).queue();
            return;
        }

        OptionMapping amountOption = event.getOption("amount");
        if (amountOption == null) {
            event.reply("Please specify the amount of messages to delete.").setEphemeral(true).queue();
            return;
        }

        int amount = amountOption.getAsInt();
        if (amount <= 0 || amount > 100) {
            event.reply("Please specify an amount between 1 and 100.").setEphemeral(true).queue();
            return;
        }

        event.deferReply(true).queue();

        MessageChannel channel = event.getChannel();
        channel.getHistory().retrievePast(amount).queue(messages -> {
            if (messages.isEmpty()) {
                event.getHook().editOriginal("No messages found to delete.").queue();
                return;
            }

            try {
                channel.purgeMessages(messages);
                event.getHook().editOriginal("✅ Successfully deleted " + messages.size() + " messages.")
                        .queue(m -> event.getHook().deleteOriginal().queueAfter(5, TimeUnit.SECONDS));
            } catch (IllegalArgumentException e) {
                event.getHook()
                        .editOriginal("❌ Some messages are too old (over 14 days) and cannot be deleted in bulk.")
                        .queue();
            }
        });
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data.addOption(OptionType.INTEGER, "amount", "Number of messages to delete (1-100)", true)
                .setDefaultPermissions(DefaultMemberPermissions.enabledFor(Permission.MESSAGE_MANAGE));
    }

    @Override
    public String getName() {
        return "purge";
    }

    @Override
    public String getDescription() {
        return "Delete a specified number of messages";
    }
}
