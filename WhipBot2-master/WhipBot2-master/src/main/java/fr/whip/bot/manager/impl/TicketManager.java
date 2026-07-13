package fr.whip.bot.manager.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.data.entity.TicketBanEntity;
import fr.whip.bot.data.entity.TicketEntity;
import fr.whip.bot.data.log.LogCategory;
import fr.whip.bot.storage.hibernate.HibernateConnection;
import org.hibernate.Session;
import org.hibernate.Transaction;

import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.entities.MessageEmbed;
import net.dv8tion.jda.api.components.actionrow.ActionRow;
import net.dv8tion.jda.api.components.buttons.Button;
import net.dv8tion.jda.api.entities.emoji.Emoji;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.config.impl.BotConfigLoader;
import java.awt.Color;
import java.time.Duration;
import java.time.Instant;
import net.dv8tion.jda.api.interactions.InteractionHook;
import net.dv8tion.jda.api.entities.User;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.entities.channel.concrete.Category;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class TicketManager {

    private final HibernateConnection hibernateConnection;
    private final WhipBot main;
    private ScheduledExecutorService reminderService;

    public TicketManager(WhipBot main, HibernateConnection hibernateConnection) {
        this.main = main;
        this.hibernateConnection = hibernateConnection;
    }

    public void start(net.dv8tion.jda.api.JDA jda) {
        this.reminderService = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "Ticket-Reminder-Task");
            thread.setDaemon(true);
            return thread;
        });

        this.reminderService.scheduleAtFixedRate(() -> checkReminders(jda), 1, 10, TimeUnit.MINUTES);
    }

    public void stop() {
        if (reminderService != null) {
            reminderService.shutdown();
        }
    }

    private void checkReminders(net.dv8tion.jda.api.JDA jda) {
        if (jda == null) {
            return;
        }
        try {
            List<TicketEntity> tickets = findAll();
            Instant now = Instant.now();

            for (TicketEntity ticket : tickets) {
                // Si le staff a envoyé le dernier message, on attend la réponse du
                // client : on ne ping rien.
                if (ticket.isAwaitingUserReply()) {
                    continue;
                }

                if (ticket.getLastActivity() == null) {
                    continue;
                }

                // On attend le staff : on relance une seule fois à 1h, une fois à 12h
                // et une fois à 24h après le dernier message du client. lastActivity
                // n'est PAS réinitialisé par le ping, donc le compteur continue de
                // tourner depuis le message du client.
                long hoursInactive = Duration.between(ticket.getLastActivity(), now).toHours();

                int targetStage;
                if (hoursInactive >= 24) {
                    targetStage = 3;
                } else if (hoursInactive >= 12) {
                    targetStage = 2;
                } else if (hoursInactive >= 1) {
                    targetStage = 1;
                } else {
                    targetStage = 0;
                }

                if (targetStage > ticket.getStaffReminderStage()) {
                    net.dv8tion.jda.api.entities.channel.concrete.TextChannel channel = jda
                            .getTextChannelById(ticket.getStaffChannelId());
                    if (channel != null) {
                        long hours = switch (targetStage) {
                            case 1 -> 1;
                            case 2 -> 12;
                            default -> 24;
                        };
                        channel.sendMessage("@everyone ⚠️ No staff has replied to this ticket for over "
                                + hours + (hours > 1 ? " hours" : " hour") + "!").queue();
                    }
                    ticket.setStaffReminderStage(targetStage);
                    save(ticket);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Optional<TicketEntity> findByUserDiscordId(String discordId) {
        try (Session session = hibernateConnection.getSessionFactory().openSession()) {
            return Optional.ofNullable(session.get(TicketEntity.class, discordId));
        } catch (Exception e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }

    public Optional<TicketEntity> findByStaffChannelId(String channelId) {
        try (Session session = hibernateConnection.getSessionFactory().openSession()) {
            var query = session.createQuery("FROM TicketEntity WHERE staffChannelId = :channelId", TicketEntity.class);
            query.setParameter("channelId", channelId);
            return query.uniqueResultOptional();
        } catch (Exception e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }

    public TicketEntity save(TicketEntity ticket) {
        Transaction transaction = null;
        try (Session session = hibernateConnection.getSessionFactory().openSession()) {
            transaction = session.beginTransaction();
            session.merge(ticket);
            transaction.commit();
            return ticket;
        } catch (Exception e) {
            if (transaction != null) {
                transaction.rollback();
            }
            e.printStackTrace();
            return ticket;
        }
    }

    public void delete(TicketEntity ticket) {
        Transaction transaction = null;
        try (Session session = hibernateConnection.getSessionFactory().openSession()) {
            transaction = session.beginTransaction();
            session.remove(session.contains(ticket) ? ticket : session.merge(ticket));
            transaction.commit();
        } catch (Exception e) {
            if (transaction != null) {
                transaction.rollback();
            }
            e.printStackTrace();
        }
    }

    public List<TicketEntity> findAll() {
        try (Session session = hibernateConnection.getSessionFactory().openSession()) {
            return session.createQuery("FROM TicketEntity", TicketEntity.class).list();
        }
    }

    public long getOpenTicketCount() {
        try (Session session = hibernateConnection.getSessionFactory().openSession()) {
            return session.createQuery("SELECT count(*) FROM TicketEntity", Long.class).uniqueResult();
        } catch (Exception e) {
            return 0;
        }
    }

    public void updateLastActivity(TicketEntity ticket) {
        ticket.setLastActivity(Instant.now());
        save(ticket);
    }

    public void closeTicket(net.dv8tion.jda.api.JDA jda, TicketEntity ticket, boolean staffTriggered) {
        String closedBy = staffTriggered ? "Staff" : "User";

        main.getLogManager().info(LogCategory.TICKET, ticket.getUserDiscordId(),
                "Ticket closed by " + closedBy + " | reason: " + ticket.getReason());

        main.getTranscriptManager().generateAndSend(main, jda, ticket, closedBy);

        delete(ticket);

        EmbedBuilder embed = new EmbedBuilder()
                .setTitle("📩 Ticket Closed")
                .setColor(Color.RED)
                .setDescription("Your ticket has been closed. Thank you for contacting Whip Client support!\n\n" +
                        "**Messages Cleanup:**\n" +
                        "If you would like the bot to delete its messages in this DM, please react with 🗑️ below.");

        jda.retrieveUserById(ticket.getUserDiscordId()).queue(user -> user.openPrivateChannel().queue(
                pc -> pc.sendMessageEmbeds(embed.build()).queue(
                        msg -> msg.addReaction(net.dv8tion.jda.api.entities.emoji.Emoji.fromUnicode("🗑️")).queue(),
                        err -> {
                        }),
                err -> {
                }));

        net.dv8tion.jda.api.entities.channel.concrete.TextChannel staffChannel = jda
                .getTextChannelById(ticket.getStaffChannelId());
        if (staffChannel != null) {
            staffChannel.delete().queueAfter(5, java.util.concurrent.TimeUnit.SECONDS);
        }
    }

    public void relayEmbedToUser(TicketEntity ticket, MessageEmbed embed) {
        relayEmbedToUser(ticket, embed, null);
    }

    public void relayEmbedToUser(TicketEntity ticket, MessageEmbed embed, ActionRow components) {
        main.getJda().retrieveUserById(ticket.getUserDiscordId()).queue(user -> {
            user.openPrivateChannel().queue(pc -> {
                if (components != null) {
                    pc.sendMessageEmbeds(embed).setComponents(components).queue(null, err -> {
                    });
                } else {
                    pc.sendMessageEmbeds(embed).queue(null, err -> {
                    });
                }
            });
        });
    }

    public boolean isBanned(String discordId) {
        try (Session session = hibernateConnection.getSessionFactory().openSession()) {
            return session.get(TicketBanEntity.class, discordId) != null;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public void banUser(String discordId, String reason, String bannedBy) {
        TicketBanEntity ban = new TicketBanEntity(discordId, reason, bannedBy, Instant.now());
        Transaction transaction = null;
        try (Session session = hibernateConnection.getSessionFactory().openSession()) {
            transaction = session.beginTransaction();
            session.merge(ban);
            transaction.commit();
        } catch (Exception e) {
            if (transaction != null) {
                transaction.rollback();
            }
            e.printStackTrace();
        }
    }

    public void unbanUser(String discordId) {
        Transaction transaction = null;
        try (Session session = hibernateConnection.getSessionFactory().openSession()) {
            transaction = session.beginTransaction();
            TicketBanEntity ban = session.get(TicketBanEntity.class, discordId);
            if (ban != null) {
                session.remove(ban);
            }
            transaction.commit();
        } catch (Exception e) {
            if (transaction != null) {
                transaction.rollback();
            }
            e.printStackTrace();
        }
    }

    public void createTicket(User user, String reason, InteractionHook hook, boolean ephemeral) {
        ConfigData config = main.getConfigHandler().getPrototypeConfig(BotConfigLoader.class);
        String categoryId = resolveCategoryId(reason, config);
        String guildId = config.channels().guildId();

        if (guildId == null || guildId.isEmpty()) {
            replyError(hook, user, "Bot error: Guild ID not configured.");
            return;
        }

        net.dv8tion.jda.api.entities.Guild guild = main.getJda().getGuildById(guildId);
        if (guild == null) {
            replyError(hook, user, "Bot error: Main server not found.");
            return;
        }

        Category category = guild.getCategoryById(categoryId);
        if (category == null) {
            category = guild.getCategoryById(config.channels().ticketCategoryId());
        }

        if (category == null) {
            replyError(hook, user, "Bot error: Ticket category not found.");
            return;
        }

        String discordId = user.getId();
        String reasonLabel = getReasonLabel(reason);
        String closeButtonId = "ticket:close:" + discordId;
        final Category finalCategory = category;
        final net.dv8tion.jda.api.entities.Guild finalGuild = guild;

        // The whole ticket runs through the user's DMs. If we can't message them
        // (DMs closed), abort with an error instead of creating an unusable ticket.
        user.openPrivateChannel().queue(privateChannel -> privateChannel
                .sendMessage("Your ticket has been created regarding: **" + reasonLabel
                        + "**.\nYou can now send messages here and staff will reply.")
                .setComponents(ActionRow.of(
                        Button.danger(closeButtonId, "Close Ticket")
                                .withEmoji(Emoji.fromUnicode("🔒"))))
                .queue(
                        dmMsg -> openTicketChannel(finalGuild, finalCategory, user, reason, reasonLabel, discordId,
                                hook),
                        dmErr -> replyError(hook, user,
                                "I couldn't send you a private message, so the ticket was not created. "
                                        + "Please enable **Direct Messages** from server members and try again.")),
                openErr -> replyError(hook, user,
                        "I couldn't send you a private message, so the ticket was not created. "
                                + "Please enable **Direct Messages** from server members and try again."));
    }

    private void openTicketChannel(net.dv8tion.jda.api.entities.Guild guild, Category category, User user,
            String reason, String reasonLabel, String discordId, InteractionHook hook) {
        category.createTextChannel("ticket-" + user.getName().toLowerCase().replace(" ", "-") + "-" + discordId)
                .addPermissionOverride(guild.getPublicRole(), null, EnumSet.of(Permission.VIEW_CHANNEL))
                .queue(channel -> {
                    TicketEntity ticket = new TicketEntity(discordId, channel.getId(), reason, Instant.now(),
                            Instant.now());
                    save(ticket);

                    EmbedBuilder embed = new EmbedBuilder()
                            .setTitle("\uD83D\uDCE9 Whip Client Ticket \u2014 " + reasonLabel)
                            .setColor(Color.decode("#3498db"))
                            .setThumbnail(user.getEffectiveAvatarUrl())
                            .setDescription("**Ticket Information**\n" +
                                    "\u2022 User: " + user.getAsMention() + "\n" +
                                    "\u2022 ID: **" + discordId + "**\n" +
                                    "\u2022 Category: **" + reasonLabel + "**\n\n" +
                                    "The staff will get back to you as soon as possible.\n" +
                                    "Use `/close` to close this ticket.")
                            .setFooter("Whip Client Ticket");

                    channel.sendMessage("@everyone").addEmbeds(embed.build()).queue();

                    if (hook != null) {
                        hook.deleteOriginal().queue();
                    }
                });
    }

    public String resolveCategoryId(String reason, ConfigData config) {
        if (reason == null)
            return config.channels().ticketCategoryId();
        return switch (reason.toLowerCase()) {
            case "buy" -> config.channels().buyTicketCategoryId();
            case "question", "questions" -> config.channels().questionsTicketCategoryId();
            case "hwid", "reset hwid" -> config.channels().hwidTicketCategoryId();
            case "others", "other" -> config.channels().otherTicketCategoryId();
            default -> config.channels().ticketCategoryId();
        };
    }

    public String getReasonLabel(String reason) {
        if (reason == null)
            return "\uD83D\uDCC1 Others";
        return switch (reason.toLowerCase()) {
            case "buy" -> "\uD83D\uDCB0 Buy";
            case "question", "questions" -> "\u2753 Question";
            case "hwid", "reset hwid" -> "\uD83D\uDD04 Reset HWID";
            case "others", "other" -> "\uD83D\uDCC1 Others";
            default -> "\uD83D\uDCC1 Others";
        };
    }

    private void replyError(InteractionHook hook, User user, String message) {
        if (hook != null) {
            hook.editOriginal("\u274C " + message).queue();
        } else {
            user.openPrivateChannel().queue(pc -> pc.sendMessage("\u274C " + message).queue());
        }
    }
}
