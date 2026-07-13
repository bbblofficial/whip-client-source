package fr.whip.bot.listener;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.impl.RulesCommand;
import fr.whip.bot.command.impl.TosCommand;
import fr.whip.bot.command.impl.TutoCommand;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.PermissionsData;
import fr.whip.bot.data.entity.TicketEntity;
import fr.whip.bot.util.PermissionChecker;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.entities.MessageEmbed;
import net.dv8tion.jda.api.entities.channel.ChannelType;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;
import net.dv8tion.jda.api.entities.emoji.Emoji;
import net.dv8tion.jda.api.events.message.MessageReceivedEvent;
import net.dv8tion.jda.api.components.actionrow.ActionRow;
import net.dv8tion.jda.api.components.buttons.Button;
import net.dv8tion.jda.api.interactions.components.ComponentInteraction;

import java.awt.Color;

public class PrefixCommandListener implements Listener {

    private final WhipBot main;

    public PrefixCommandListener(WhipBot main) {
        this.main = main;

        // Register button handlers for crypto selection
        main.getComponentHandler().register("crypto:btc", i -> handleButton(i, "Bitcoin", "#F7931A", "BTCEUR", "BTC", "bc1qyhtpkh7slnkg5k5nnmmrhemqvkeyykwvygjc55", "Bitcoin"));
        main.getComponentHandler().register("crypto:ltc", i -> handleButton(i, "Litecoin", "#345D9D", "LTCEUR", "LTC", "ltc1qq6432u93wxd9zdqfftlj70k75d2rc374guh2l3", "Litecoin"));
        main.getComponentHandler().register("crypto:eth", i -> handleButton(i, "Ethereum", "#3C3C3D", "ETHEUR", "ETH", "0xFA24BA07C604CA915487C4A025370263645ce58a", "ERC-20"));
        main.getComponentHandler().register("crypto:sol", i -> handleButton(i, "Solana", "#14F195", "SOLEUR", "SOL", "8rEYQUPezPpHV6xceSXQKsG5vjBkZ9xF8NYW4u4Dut3h", "Solana"));
        main.getComponentHandler().register("crypto:copy:", this::handleCopyAmount);
        main.getComponentHandler().register("crypto:copyaddr:", this::handleCopyAddress);
    }

    private void handleCopyAmount(ComponentInteraction interaction) {
        String amount = interaction.getComponentId().substring("crypto:copy:".length());
        boolean inGuild = interaction.getChannel() instanceof TextChannel;
        interaction.reply("```\n" + amount + "\n```").setEphemeral(inGuild).queue();
    }

    private void handleCopyAddress(ComponentInteraction interaction) {
        String address = interaction.getComponentId().substring("crypto:copyaddr:".length());
        boolean inGuild = interaction.getChannel() instanceof TextChannel;
        interaction.reply("```\n" + address + "\n```").setEphemeral(inGuild).queue();
    }

    @EventHandler
    public void onMessage(MessageReceivedEvent event) {
        if (event.getAuthor().isBot())
            return;
        if (event.getChannelType() != ChannelType.TEXT && event.getChannelType() != ChannelType.PRIVATE)
            return;

        String raw = event.getMessage().getContentRaw();
        if (!raw.startsWith("!"))
            return;

        String command = raw.substring(1).toLowerCase().split(" ")[0];

        PermissionsData perms = main.getConfigHandler()
                .<ConfigData>getPrototypeConfig(BotConfigLoader.class).permissions();

        switch (command) {
            case "rules":
            case "rulescustomers":
                if (!PermissionChecker.isUser(event.getAuthor(), perms.singerieUserId())) return;
                break;
            case "tuto":
            case "paypal":
            case "crypto":
            case "tos":
                if (event.getMember() == null || !event.getMember().hasPermission(Permission.ADMINISTRATOR)) return;
                break;
            default:
                return;
        }

        switch (command) {
            case "rules":
                handleRules(event);
                break;
            case "rulescustomers":
                handleRulesCustomer(event);
                break;
            case "tuto":
                handleTuto(event);
                break;
            case "paypal":
                handlePaypal(event);
                break;
            case "crypto":
                handleCrypto(event);
                break;
            case "tos":
                handleTos(event);
                break;
        }
    }

    private void handleRules(MessageReceivedEvent event) {
        event.getMessage().delete().queue();
        event.getChannel().sendMessageEmbeds(RulesCommand.buildEmbed().build())
                .setComponents(ActionRow.of(Button.success(RulesCommand.ACCEPT_BUTTON_ID, "✅ Accept rules")))
                .queue();
    }

    private void handleRulesCustomer(MessageReceivedEvent event) {
        event.getMessage().delete().queue();
        event.getChannel().sendMessageEmbeds(RulesCommand.buildEmbed().build())
                .setComponents(ActionRow.of(Button.success(RulesCommand.CUSTOMER_BUTTON_ID, "✅ Accept rules")))
                .queue();
    }

    private void handleTuto(MessageReceivedEvent event) {
        event.getMessage().delete().queue();
        MessageEmbed embed = TutoCommand.buildEmbed().build();
        event.getChannel().sendMessageEmbeds(embed).queue();
        relayToTicketUser(event, embed);
    }

    private void handlePaypal(MessageReceivedEvent event) {
        EmbedBuilder embed = new EmbedBuilder()
                .setTitle("💳 PayPal Payment Information")
                .setColor(Color.decode("#00457C"))
                .setDescription("Please send your payment of **100 EUR** to the following PayPal link:\n\n" +
                        "**https://paypal.me/TAlmansa**\n\n" +
                        "⚠️ **IMPORTANT INSTRUCTIONS:**\n" +
                        "• You MUST send the money using **Friends and Family (F&F)**.\n" +
                        "• Do **NOT** put any note or message in the payment.\n" +
                        "• Send a screenshot of the confirmation once done.")
                .setFooter("Whip Payments");
        MessageEmbed built = embed.build();
        event.getChannel().sendMessageEmbeds(built).queue();
        relayToTicketUser(event, built);
    }

    private void relayToTicketUser(MessageReceivedEvent event, MessageEmbed embed) {
        if (!(event.getChannel() instanceof TextChannel textChannel))
            return;
        main.getTicketManager().findByStaffChannelId(textChannel.getId())
                .ifPresent(ticket -> main.getTicketManager().relayEmbedToUser(ticket, embed));
    }

    private void handleTos(MessageReceivedEvent event) {
        event.getMessage().delete().queue();
        MessageEmbed embed = TosCommand.buildEmbed().build();
        event.getChannel().sendMessageEmbeds(embed).queue();
        relayToTicketUser(event, embed);
    }

    private void handleCrypto(MessageReceivedEvent event) {
        EmbedBuilder embed = new EmbedBuilder()
                .setTitle("🪙 Crypto Payment Selection")
                .setColor(Color.decode("#3498db"))
                .setDescription(
                        "Please select your preferred cryptocurrency to pay your **100 EUROS** worth of crypto below:")
                .setFooter("Whip Payments");

        MessageEmbed built = embed.build();
        ActionRow buttons = ActionRow.of(
                Button.secondary("crypto:btc", "Bitcoin").withEmoji(Emoji.fromUnicode("\uD83D\uDCB0")),
                Button.secondary("crypto:ltc", "Litecoin").withEmoji(Emoji.fromUnicode("\uD83E\uDE99")),
                Button.secondary("crypto:eth", "Ethereum").withEmoji(Emoji.fromUnicode("\uD83D\uDCA0")),
                Button.secondary("crypto:sol", "Solana").withEmoji(Emoji.fromUnicode("\u2600\uFE0F")));

        event.getChannel().sendMessageEmbeds(built)
                .setComponents(buttons)
                .queue();

        if (event.getChannel() instanceof TextChannel textChannel) {
            main.getTicketManager().findByStaffChannelId(textChannel.getId())
                    .ifPresent(ticket -> main.getJda().retrieveUserById(ticket.getUserDiscordId()).queue(user ->
                            user.openPrivateChannel().queue(pc ->
                                    pc.sendMessageEmbeds(built)
                                            .setComponents(buttons)
                                            .queue(null, err -> {}))));
        }
    }

    private void handleButton(ComponentInteraction interaction, String name, String color, String symbol,
            String shortName, String address, String network) {
        double price = main.getCryptoManager().getPrice(symbol);

        if (price == 0.0) {
            interaction.reply("⏳ Prices are being retrieved, please try again in a moment...").setEphemeral(true)
                    .queue();
            return;
        }

        double amountEur = 100.0;
        double amount = amountEur / price;
        String formattedAmount = String.format("%.8f", amount).replace(",", ".");

        EmbedBuilder embed = new EmbedBuilder()
                .setTitle("🪙 Crypto Payment Information — " + name)
                .setColor(Color.decode(color))
                .setDescription(
                        "Please send exactly **100 EUROS** worth of " + name + ".\n\n" +
                                "Network: **" + network + "**\n" +
                                "Address: `" + address + "`\n" +
                                "Amount to send: **" + formattedAmount + " " + shortName + "**\n\n" +
                                "⚠️ *Cryptocurrency prices are volatile. These amounts are accurate for the current market rate. Please send within 15 minutes.*")
                .setFooter("Prices updated automatically every minute from Binance");

        MessageEmbed resultEmbed = embed.build();
        Button copyBtn = Button.secondary("crypto:copy:" + formattedAmount + " " + shortName, "Copy Amount")
                .withEmoji(Emoji.fromUnicode("\uD83D\uDCCB"));
        Button copyAddrBtn = Button.secondary("crypto:copyaddr:" + address, "Copy Address")
                .withEmoji(Emoji.fromUnicode("\uD83D\uDCC2"));
        ActionRow row = ActionRow.of(copyBtn, copyAddrBtn);
        interaction.editMessageEmbeds(resultEmbed)
                .setComponents(row)
                .queue();

        // If an admin selected in the staff channel, relay the payment info to the
        // customer's DM. If the customer selected in their own DM, post the chosen
        // crypto into their ticket so the staff can see it.
        if (interaction.getChannel() instanceof TextChannel textChannel) {
            java.util.Optional<TicketEntity> ticketOpt = main.getTicketManager()
                    .findByStaffChannelId(textChannel.getId());
            ticketOpt.ifPresent(ticket -> main.getJda().retrieveUserById(ticket.getUserDiscordId()).queue(user ->
                    user.openPrivateChannel().queue(pc ->
                            pc.sendMessageEmbeds(resultEmbed)
                                    .setComponents(row)
                                    .queue(null, err -> {}))));
        } else {
            main.getTicketManager().findByUserDiscordId(interaction.getUser().getId()).ifPresent(ticket -> {
                TextChannel staffChannel = main.getJda().getTextChannelById(ticket.getStaffChannelId());
                if (staffChannel != null) {
                    EmbedBuilder notice = new EmbedBuilder()
                            .setColor(Color.decode(color))
                            .setDescription("💰 " + interaction.getUser().getAsMention() + " selected **" + name
                                    + "** (" + network + ") — **" + formattedAmount + " " + shortName + "** to pay.");
                    staffChannel.sendMessageEmbeds(notice.build()).queue();
                }
            });
        }
    }
}
