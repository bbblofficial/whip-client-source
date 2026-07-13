package fr.whip.bot.command.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.entities.Member;
import net.dv8tion.jda.api.entities.Message;
import net.dv8tion.jda.api.entities.channel.concrete.ThreadChannel;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.DefaultMemberPermissions;
import net.dv8tion.jda.api.interactions.commands.OptionMapping;
import net.dv8tion.jda.api.interactions.commands.OptionType;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;
import net.dv8tion.jda.api.interactions.commands.build.SubcommandData;

import java.awt.Color;

public record ReportCommand(WhipBot main) implements IParentCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        String subcommand = event.getSubcommandName();
        if (subcommand == null)
            return;

        switch (subcommand) {
            case "validate" -> handleStatus(event, "validate");
            case "refuse" -> handleStatus(event, "refuse");
            case "inprogress" -> handleStatus(event, "inprogress");
        }
    }

    private void handleStatus(SlashCommandInteractionEvent event, String statusValue) {
        Member member = event.getMember();
        if (member == null
                || !(member.hasPermission(Permission.ADMINISTRATOR) || member.hasPermission(Permission.MANAGE_SERVER))) {
            event.reply("You don't have permission to use this command.").setEphemeral(true).queue();
            return;
        }

        event.deferReply(true).queue();

        String msgId = null;
        OptionMapping idOption = event.getOption("message_id");
        if (idOption != null) {
            msgId = idOption.getAsString();
        } else if (event.getChannel() instanceof ThreadChannel thread) {
            msgId = thread.getId();
        }

        if (msgId == null) {
            event.getHook().sendMessage(
                    "❌ Please use the message ID or use this command in the report thread.")
                    .queue();
            return;
        }

        final String finalId = msgId;
        event.getChannel().retrieveMessageById(finalId).queue(msg -> {
            updateEmbed(event, msg, statusValue);
        }, err -> {
            if (event.getChannel() instanceof ThreadChannel thread) {
                thread.getParentChannel().asStandardGuildMessageChannel().retrieveMessageById(finalId).queue(msg -> {
                    updateEmbed(event, msg, statusValue);
                }, secondErr -> event.getHook().sendMessage("❌ Could not find the original report.").queue());
            } else {
                event.getHook().sendMessage("❌ Report not found.").queue();
            }
        });
    }

    private void updateEmbed(SlashCommandInteractionEvent event, Message msg, String statusValue) {
        if (msg.getEmbeds().isEmpty()) {
            event.getHook().sendMessage("❌ This message does not contain an embed.").queue();
            return;
        }

        String statusText;
        Color color;

        switch (statusValue.toLowerCase()) {
            case "validate" -> {
                statusText = "✅ Validated";
                color = Color.GREEN;
            }
            case "refuse" -> {
                statusText = "❌ Refused";
                color = Color.RED;
            }
            case "inprogress" -> {
                statusText = "🔄 In Progress";
                color = Color.ORANGE;
            }
            default -> {
                statusText = statusValue;
                color = Color.GRAY;
            }
        }

        EmbedBuilder embed = new EmbedBuilder(msg.getEmbeds().get(0));
        embed.getFields().removeIf(f -> (f.getName() != null && f.getName().contains("Status"))
                || (f.getValue() != null && f.getValue().contains("In waiting")));
        embed.addField("📊 Status", "`" + statusText + "`", true);
        embed.setColor(color);

        msg.editMessageEmbeds(embed.build()).queue(success -> {
            event.getHook().sendMessage("✅ Report status updated: **" + statusText + "**").queue();
        }, err -> {
            event.getHook().sendMessage("❌ Error: " + err.getMessage()).queue();
        });
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data
                .setDefaultPermissions(
                        DefaultMemberPermissions.enabledFor(Permission.ADMINISTRATOR, Permission.MANAGE_SERVER))
                .addSubcommands(
                        new SubcommandData("validate", "Mark a bug report as validated")
                                .addOption(OptionType.STRING, "message_id",
                                        "The message ID (optional if used in a thread)", false),
                        new SubcommandData("refuse", "Mark a bug report as refused")
                                .addOption(OptionType.STRING, "message_id",
                                        "The message ID (optional if used in a thread)", false),
                        new SubcommandData("inprogress", "Mark a bug report as in progress")
                                .addOption(OptionType.STRING, "message_id",
                                        "The message ID (optional if used in a thread)", false));
    }

    @Override
    public String getName() {
        return "report";
    }

    @Override
    public String getDescription() {
        return "Manage bug reports";
    }
}
