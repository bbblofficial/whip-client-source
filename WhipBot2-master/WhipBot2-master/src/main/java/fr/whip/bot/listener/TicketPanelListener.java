package fr.whip.bot.listener;

import fr.whip.bot.WhipBot;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.entity.TicketEntity;
import fr.whip.bot.manager.impl.TicketManager;
import fr.whip.bot.util.MembershipChecker;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.components.actionrow.ActionRow;
import net.dv8tion.jda.api.components.selections.StringSelectMenu;
import net.dv8tion.jda.api.entities.Guild;
import net.dv8tion.jda.api.entities.channel.concrete.Category;
import net.dv8tion.jda.api.events.interaction.component.ButtonInteractionEvent;
import net.dv8tion.jda.api.events.interaction.component.StringSelectInteractionEvent;
import net.dv8tion.jda.api.interactions.InteractionHook;

import java.awt.Color;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Optional;

public class TicketPanelListener implements Listener {

        private final WhipBot main;

        public TicketPanelListener(WhipBot main) {
                this.main = main;
        }

        @EventHandler
        public void onButton(ButtonInteractionEvent event) {
                if (event.getComponentId().equals("ticket:close")) {
                        Optional<TicketEntity> ticketOpt = main.getTicketManager()
                                        .findByUserDiscordId(event.getUser().getId());
                        if (ticketOpt.isPresent()) {
                                event.reply("✅ Ticket closed!").setEphemeral(true).queue();
                                main.getTicketManager().closeTicket(event.getJDA(), ticketOpt.get(), false);
                        } else {
                                event.reply("❌ You do not have an open ticket.").setEphemeral(true).queue();
                        }
                        return;
                }

                if (!event.getComponentId().equals("ticket:create"))
                        return;

                if (main.getTicketManager().isBanned(event.getUser().getId())) {
                        event.reply("❌ You are banned from the ticket system.").setEphemeral(true).queue();
                        return;
                }

                String discordId = event.getUser().getId();
                TicketManager ticketManager = main.getTicketManager();

                if (ticketManager.findByUserDiscordId(discordId).isPresent()) {
                        event.reply("❌ You already have an open ticket!").setEphemeral(true).queue();
                        return;
                }

                StringSelectMenu menu = StringSelectMenu.create("ticket:category")
                                .setPlaceholder("Choose a category...")
                                .addOption("Purchase", "Buy", "Buy a license, transfer coins...",
                                                net.dv8tion.jda.api.entities.emoji.Emoji.fromUnicode("💰"))
                                .addOption("Questions", "Question", "Ask a question",
                                                net.dv8tion.jda.api.entities.emoji.Emoji.fromUnicode("❓"))
                                .addOption("Reset HWID", "HWID", "Request an HWID reset",
                                                net.dv8tion.jda.api.entities.emoji.Emoji.fromUnicode("🔄"))
                                .addOption("Other", "Others", "Other requests",
                                                net.dv8tion.jda.api.entities.emoji.Emoji.fromUnicode("💬"))
                                .build();

                if (event.isFromGuild()) {
                        event.reply("Select a category for your ticket:")
                                        .setComponents(ActionRow.of(menu))
                                        .setEphemeral(true)
                                        .queue();
                        return;
                }

                event.deferReply(true).queue();
                MembershipChecker.check(event.getJDA(), event.getUser(),
                                () -> event.getHook().sendMessage("Select a category for your ticket:")
                                                .setComponents(ActionRow.of(menu))
                                                .queue(),
                                () -> event.getHook().sendMessage(
                                                "❌ Join the **Whip Community** server to open a ticket.").queue());
        }

        @EventHandler
        public void onSelectMenu(StringSelectInteractionEvent event) {
                if (!event.getComponentId().equals("ticket:category"))
                        return;

                if (main.getTicketManager().isBanned(event.getUser().getId())) {
                        event.reply("❌ You are banned from the ticket system.").setEphemeral(true).queue();
                        return;
                }

                String discordId = event.getUser().getId();
                TicketManager ticketManager = main.getTicketManager();

                if (ticketManager.findByUserDiscordId(discordId).isPresent()) {
                        event.reply("❌ You already have an open ticket!").setEphemeral(true).queue();
                        return;
                }

                String reason = event.getValues().get(0);
                event.deferReply(true).queue();

                if (event.isFromGuild()) {
                        ticketManager.createTicket(event.getUser(), reason, event.getHook(), true);
                        return;
                }

                MembershipChecker.check(event.getJDA(), event.getUser(),
                                () -> ticketManager.createTicket(event.getUser(), reason, event.getHook(), true),
                                () -> event.getHook().sendMessage(
                                                "❌ Join the **Whip Community** server to open a ticket.").queue());
        }
}
