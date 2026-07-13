package fr.whip.bot.command.impl;

import at.favre.lib.crypto.bcrypt.BCrypt;
import fr.whip.api.model.User;
import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.log.LogCategory;
import fr.whip.bot.data.log.LogLevel;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.entities.Guild;
import net.dv8tion.jda.api.entities.channel.attribute.IInviteContainer;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;
import net.dv8tion.jda.api.entities.channel.unions.DefaultGuildChannelUnion;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.OptionType;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

import java.awt.Color;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

public record RegisterCommand(WhipBot main) implements IParentCommand {

    private static final Color BRAND = Color.decode("#3498db");
    private static final Color ERROR = Color.decode("#ED4245");

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        String discordId = event.getUser().getId();

        if (main.getUserManager().existsByDiscordId(discordId)) {
            event.replyEmbeds(embed(event, "Already Registered", "You already have an account!", ERROR).build())
                    .setEphemeral(true).queue();
            return;
        }

        String key = event.getOption("key").getAsString();

        main.getLicenseManager().findByLicenseKeyFresh(key).ifPresentOrElse(license -> {
            if (license.getUser() != null) {
                main.getLogManager().warn(LogCategory.AUTH, discordId, "Tried to register with already-used key: " + key);
                event.replyEmbeds(embed(event, "License Already Used", "This license key is already linked to another account!", ERROR).build())
                        .setEphemeral(true).queue();
                return;
            }

            String username = event.getOption("username").getAsString();
            String password = event.getOption("password").getAsString();

            String passwordHash = BCrypt.withDefaults().hashToString(12, password.toCharArray());

            User user = new User();
            user.setUsername(username);
            user.setPasswordHash(passwordHash);
            user.setDiscordId(discordId);
            user.setCreatedAt(Instant.now());

            // save() does session.merge() and returns the managed copy — the original
            // instance keeps id=null, so we must use the returned User. Otherwise the
            // license's @ManyToOne points to a transient User and the flush fails.
            User savedUser = main.getUserManager().save(user);

            license.setUser(savedUser);
            main.getLicenseManager().save(license);

            main.getLogManager().info(LogCategory.AUTH, discordId, "Registered as '" + username + "' with key " + key);
            main.getAuditManager().event("user.register", "user", savedUser.getId(),
                    "Inscription via Discord (" + event.getUser().getName() + ")");
            event.replyEmbeds(embed(event, "Account Registered",
                            "Welcome, **" + username + "**! Your account is ready — you can now use `/download`.\n\n" +
                                    "📩 Check your DMs for your personal invite to the customer server.", BRAND).build())
                    .setEphemeral(true).queue();

            sendCustomerInvite(event, discordId);
        }, () -> {
            main.getLogManager().warn(LogCategory.AUTH, discordId, "Register attempt with invalid key: " + key);
            event.replyEmbeds(embed(event, "Invalid Key", "License key not found.", ERROR).build())
                    .setEphemeral(true).queue();
        });
    }

    /** Builds an embed in the standard Whip style (self avatar thumbnail + "Whip Client" footer). */
    private EmbedBuilder embed(SlashCommandInteractionEvent event, String title, String description, Color color) {
        return new EmbedBuilder()
                .setTitle(title)
                .setColor(color)
                .setThumbnail(event.getJDA().getSelfUser().getEffectiveAvatarUrl())
                .setDescription(description)
                .setFooter("Whip Client");
    }

    /**
     * Creates a single-use invite to the customer Discord server and DMs it to the freshly
     * registered user. The account already exists at this point, so a missing invite never
     * breaks registration — but instead of failing silently we surface the reason as an
     * ephemeral follow-up, and fall back to posting the invite ephemerally if the DM fails.
     */
    private void sendCustomerInvite(SlashCommandInteractionEvent event, String discordId) {
        ConfigData config = main.getConfigHandler().getPrototypeConfig(BotConfigLoader.class);
        String customerGuildId = config.channels().customerGuildId();
        if (customerGuildId == null || customerGuildId.isEmpty()) {
            main.getLogManager().warn(LogCategory.AUTH, discordId, "Cannot create customer invite: customer guild ID not configured");
            followupError(event, "The customer server is not configured. Please contact an admin.");
            return;
        }

        Guild guild = event.getJDA().getGuildById(customerGuildId);
        if (guild == null) {
            main.getLogManager().warn(LogCategory.AUTH, discordId, "Cannot create customer invite: guild not found / bot not a member (" + customerGuildId + ")");
            followupError(event, "Couldn't create your invite — the bot is not on the customer server. Please contact an admin.");
            return;
        }

        IInviteContainer channel = resolveInviteChannel(guild);
        if (channel == null) {
            main.getLogManager().warn(LogCategory.AUTH, discordId, "Cannot create customer invite: bot lacks Create Invite permission in guild " + customerGuildId);
            followupError(event, "Couldn't create your invite — the bot is missing the **Create Invite** permission. Please contact an admin.");
            return;
        }

        channel.createInvite()
                .setUnique(true)
                .setMaxUses(1)
                .reason("First-registration invite for Discord user " + discordId)
                .queue(invite -> {
                    EmbedBuilder inviteEmbed = embed(event, "Welcome to Whip 🎟️",
                            "Here is your personal **single-use** invite to the customer server:\n\n" +
                                    "**[→ Join the customer server](" + invite.getUrl() + ")**\n\n" +
                                    "⚠️ This invite can only be used once.\n" +
                                    "⏱️ This message will be deleted in 1 minute.", BRAND);

                    event.getUser().openPrivateChannel().queue(pc ->
                                    pc.sendMessageEmbeds(inviteEmbed.build()).queue(
                                            msg -> {
                                                msg.delete().queueAfter(1, TimeUnit.MINUTES, s -> {}, t -> {});
                                                main.getLogManager().info(LogCategory.AUTH, discordId, "Sent single-use customer invite");
                                            },
                                            err -> {
                                                main.getLogManager().warn(LogCategory.AUTH, discordId, "Created invite but failed to DM user (DMs closed?): " + err.getMessage());
                                                followupInvite(event, invite.getUrl());
                                            }
                                    ),
                            err -> {
                                main.getLogManager().warn(LogCategory.AUTH, discordId, "Could not open DM to send invite: " + err.getMessage());
                                followupInvite(event, invite.getUrl());
                            });
                }, err -> {
                    main.getLogManager().warn(LogCategory.AUTH, discordId, "Failed to create customer invite: " + err.getMessage());
                    followupError(event, "Couldn't create your invite right now. Please contact an admin.");
                });
    }

    /** Ephemeral follow-up carrying the invite link, used when the DM could not be delivered. */
    private void followupInvite(SlashCommandInteractionEvent event, String inviteUrl) {
        event.getHook().sendMessageEmbeds(embed(event, "Your invite 🎟️",
                        "We couldn't DM you (your DMs may be closed), so here is your personal **single-use** invite:\n\n" +
                                "**[→ Join the customer server](" + inviteUrl + ")**\n\n" +
                                "⚠️ This invite can only be used once.", BRAND).build())
                .setEphemeral(true).queue(m -> {}, t -> {});
    }

    /** Ephemeral follow-up explaining why the invite could not be created. */
    private void followupError(SlashCommandInteractionEvent event, String reason) {
        event.getHook().sendMessageEmbeds(embed(event, "Invite Unavailable", reason, ERROR).build())
                .setEphemeral(true).queue(m -> {}, t -> {});
    }

    /** Picks a channel the bot can create invites in: the guild's default channel, else any text channel with permission. */
    private IInviteContainer resolveInviteChannel(Guild guild) {
        DefaultGuildChannelUnion defaultChannel = guild.getDefaultChannel();
        if (defaultChannel instanceof IInviteContainer container
                && guild.getSelfMember().hasPermission(defaultChannel, Permission.CREATE_INSTANT_INVITE)) {
            return container;
        }

        for (TextChannel tc : guild.getTextChannels()) {
            if (guild.getSelfMember().hasPermission(tc, Permission.CREATE_INSTANT_INVITE)) {
                return tc;
            }
        }
        return null;
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data
                .addOption(OptionType.STRING, "key", "Your license key given by an admin", true)
                .addOption(OptionType.STRING, "username", "Choose a username", true)
                .addOption(OptionType.STRING, "password", "Choose a password", true);
    }

    @Override
    public String getName() { return "register"; }

    @Override
    public String getDescription() { return "Register your account with a valid license key"; }
}
