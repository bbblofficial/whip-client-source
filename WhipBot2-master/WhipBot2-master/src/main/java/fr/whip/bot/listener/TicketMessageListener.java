package fr.whip.bot.listener;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import fr.whip.bot.WhipBot;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.entity.TicketEntity;
import fr.whip.bot.data.entity.TicketMessage;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.entities.Message;
import net.dv8tion.jda.api.entities.channel.ChannelType;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;
import net.dv8tion.jda.api.entities.emoji.Emoji;
import net.dv8tion.jda.api.events.message.MessageReceivedEvent;
import net.dv8tion.jda.api.events.message.react.MessageReactionAddEvent;
import net.dv8tion.jda.api.utils.FileUpload;
import net.dv8tion.jda.api.components.actionrow.ActionRow;
import net.dv8tion.jda.api.components.buttons.Button;
import net.dv8tion.jda.api.interactions.components.ComponentInteraction;
import net.dv8tion.jda.api.components.textinput.*;
import net.dv8tion.jda.api.components.label.*;
import net.dv8tion.jda.api.interactions.modals.*;
import net.dv8tion.jda.api.modals.*;
import net.dv8tion.jda.api.components.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.Color;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class TicketMessageListener implements Listener {

    private static final Logger LOGGER = LoggerFactory.getLogger(TicketMessageListener.class);
    private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();

    private final WhipBot main;
    private final Map<String, PendingStaffMessage> pendingMessages = new ConcurrentHashMap<>();

    public TicketMessageListener(WhipBot main) {
        this.main = main;

        // Register interaction handlers
        main.getComponentHandler().register("ticket:staff:confirm:", this::handleStaffConfirm);
        main.getComponentHandler().register("ticket:staff:edit:", this::handleStaffEditRequest);
        main.getComponentHandler().registerModal("ticket:staff:modal:", this::handleStaffModalSubmit);
    }

    @EventHandler
    public void onMessage(MessageReceivedEvent event) {
        if (event.getAuthor().isBot())
            return;

        if (event.getChannelType() == ChannelType.TEXT) {
            handleStaffMessage(event);
        } else if (event.getChannelType() == ChannelType.PRIVATE) {
            handleUserMessage(event);
        }
    }

    private void handleStaffMessage(MessageReceivedEvent event) {
        TextChannel channel = event.getChannel().asTextChannel();
        main.getTicketManager().findByStaffChannelId(channel.getId()).ifPresent(ticket -> {
            String content = event.getMessage().getContentRaw();

            if (content.startsWith("!"))
                return;

            List<Message.Attachment> attachments = event.getMessage().getAttachments();

            // Un fichier (DLL, image, etc.) : aucune traduction, aucun menu de
            // confirmation -> on l'envoie directement au client, tel quel.
            if (!attachments.isEmpty()) {
                sendStaffFileDirect(ticket, content, attachments, event.getAuthor().getId(),
                        event.getAuthor().getName(), channel, event.getMessage());
                return;
            }

            // Delete original staff message to keep channel clean before verification
            event.getMessage().delete().queue();

            initiateStaffVerification(ticket, content, attachments, event.getAuthor().getName(), channel);
        });
    }

    private void sendStaffFileDirect(TicketEntity ticket, String content, List<Message.Attachment> attachments,
            String staffId, String staffName, TextChannel channel, Message originalMessage) {
        // Download all files BEFORE deleting the message — Discord CDN URLs become
        // invalid once the source message is deleted, so we must have the bytes in
        // memory first.
        List<CompletableFuture<FileUpload>> futures = new ArrayList<>();
        for (Message.Attachment attachment : attachments) {
            futures.add(attachment.getProxy().download()
                    .thenApply(is -> FileUpload.fromData(is, attachment.getFileName())));
        }

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).thenAccept(v -> {
            List<FileUpload> uploads = futures.stream().map(CompletableFuture::join).toList();

            // Relay pre-downloaded files to the client's DM.
            EmbedBuilder userEmbed = new EmbedBuilder()
                    .setTitle("📩 Whip Client Support — Staff Message")
                    .setColor(Color.decode("#3498db"))
                    .setFooter("Our team is here to help! • Response by " + staffName);
            if (content != null && !content.isBlank()) {
                userEmbed.setDescription(content);
            }

            main.getJda().retrieveUserById(ticket.getUserDiscordId()).queue(user ->
                    user.openPrivateChannel().queue(pc ->
                            pc.sendFiles(uploads).addEmbeds(userEmbed.build()).queue(
                                    null, err -> LOGGER.error("Failed to send file relay to user DM", err))));

            // Update ticket state now that staff replied.
            main.getTicketManager().findByUserDiscordId(ticket.getUserDiscordId()).ifPresent(t -> {
                t.setAwaitingUserReply(true);
                t.setLastActivity(Instant.now());
                t.setStaffReminderStage(0);
                main.getTicketManager().save(t);
            });

            // Log en base.
            TicketMessage msg = new TicketMessage(ticket.getUserDiscordId(), staffId, staffName, true, content);
            main.getTicketMessageManager().save(msg);

            // Clean staff channel only after downloads are secured.
            originalMessage.delete().queue(null, err -> {
            });
            channel.sendMessageEmbeds(new EmbedBuilder()
                    .setTitle("📎 Fichier envoyé")
                    .setColor(Color.decode("#2ecc71"))
                    .setDescription((content == null || content.isBlank() ? "" : content + "\n\n")
                            + attachments.size() + " fichier(s) envoyé(s) directement au client.")
                    .setFooter("Envoyé par " + staffName)
                    .build())
                    .queue();
        }).exceptionally(err -> {
            LOGGER.error("Failed to download attachments for staff relay", err);
            channel.sendMessage("❌ Échec du téléchargement du/des fichier(s) — impossible de les relayer au client.")
                    .queue();
            return null;
        });
    }

    private void initiateStaffVerification(TicketEntity ticket, String content, List<Message.Attachment> attachments,
            String staffName, TextChannel channel) {
        String targetLang = ticket.getDetectedLanguage();

        // User has never spoken yet → no detected language. Don't auto-translate
        // to English; relay the staff message as-is in the base language.
        if (targetLang == null || targetLang.isBlank()) {
            showVerificationEmbed(ticket, content, content, "Base language (no translation)", attachments, staffName,
                    channel);
            return;
        }

        final String finalTargetLang = targetLang;

        if (targetLang.equalsIgnoreCase("French")) {
            // No translation needed, but we still show verification as requested for
            // "confirmation"
            showVerificationEmbed(ticket, content, content, "French (No change)", attachments, staffName, channel);
        } else {
            translate(content, targetLang).thenAccept(translatedText -> {
                showVerificationEmbed(ticket, translatedText, content, finalTargetLang, attachments, staffName,
                        channel);
            });
        }
    }

    private void showVerificationEmbed(TicketEntity ticket, String translatedText, String originalText,
            String targetLang, List<Message.Attachment> attachments, String staffName, TextChannel channel) {
        String sessionId = UUID.randomUUID().toString();
        pendingMessages.put(sessionId,
                new PendingStaffMessage(ticket, originalText, translatedText, targetLang, attachments, staffName));

        String safeOriginal = (originalText == null || originalText.isBlank()) ? "*(aucun texte)*" : originalText;
        String safeTranslated = (translatedText == null || translatedText.isBlank()) ? "*(aucun texte)*"
                : translatedText;

        EmbedBuilder verifyEmbed = new EmbedBuilder()
                .setTitle("\u26A0\uFE0F Staff Message Verification")
                .setColor(Color.decode("#f1c40f"))
                .addField("Original Text", safeOriginal, false)
                .addField("AI Translation (" + targetLang + ")", safeTranslated, false)
                .setFooter("This message has NOT been sent to the client yet.");

        Button confirmBtn = Button.success("ticket:staff:confirm:" + sessionId, "Confirm & Send")
                .withEmoji(Emoji.fromUnicode("\u2705"));
        Button editBtn = Button.primary("ticket:staff:edit:" + sessionId, "Edit Message")
                .withEmoji(Emoji.fromUnicode("\u270F\uFE0F"));

        channel.sendMessageEmbeds(verifyEmbed.build())
                .setComponents(ActionRow.of(confirmBtn, editBtn))
                .queue(m -> {
                    // Expire session after 10 minutes
                    CompletableFuture.delayedExecutor(10, TimeUnit.MINUTES).execute(() -> {
                        pendingMessages.remove(sessionId);
                        m.delete().queue(null, t -> {
                        }); // Try to delete if it's still there
                    });
                });
    }

    private void handleStaffConfirm(ComponentInteraction interaction) {
        String sessionId = interaction.getComponentId().substring("ticket:staff:confirm:".length());
        PendingStaffMessage pending = pendingMessages.remove(sessionId);

        if (pending == null) {
            interaction.reply("\u274C This session has expired or been already processed.").setEphemeral(true).queue();
            return;
        }

        // Send to client
        sendStaffRelayToClient(pending.ticket, pending.translatedText, pending.staffName, pending.attachments);

        // Le staff vient de répondre -> on attend désormais la réponse du client.
        // Du coup, aucun ping staff tant que le client n'a pas répondu.
        // On relit le ticket à jour pour ne pas écraser un éventuel message du
        // client arrivé entre-temps.
        main.getTicketManager().findByUserDiscordId(pending.ticket.getUserDiscordId()).ifPresent(ticket -> {
            ticket.setAwaitingUserReply(true);
            ticket.setLastActivity(Instant.now());
            ticket.setStaffReminderStage(0);
            main.getTicketManager().save(ticket);
        });

        // Delete verification message and send a clean new one
        interaction.getMessage().delete().queue();
        interaction.getChannel().sendMessageEmbeds(new EmbedBuilder()
                .setTitle("\u2705 Message Sent")
                .setColor(Color.decode("#2ecc71"))
                .setDescription("**Original:**\n" + pending.originalText + "\n\n**Translated:**\n" + pending.translatedText)
                .setFooter("Sent by " + pending.staffName)
                .build())
                .queue();
        interaction.deferEdit().queue();

        // Log to database
        TicketMessage msg = new TicketMessage(
                pending.ticket.getUserDiscordId(),
                interaction.getUser().getId(),
                pending.staffName,
                true,
                pending.originalText);
        main.getTicketMessageManager().save(msg);
    }

    private void handleStaffEditRequest(ComponentInteraction interaction) {
        String sessionId = interaction.getComponentId().substring("ticket:staff:edit:".length());
        PendingStaffMessage pending = pendingMessages.get(sessionId);

        if (pending == null) {
            interaction.reply("\u274C This session has expired.").setEphemeral(true).queue();
            return;
        }

        TextInput body = TextInput.create("body", TextInputStyle.PARAGRAPH)
                .setPlaceholder("Enter the new message content...")
                .setValue(pending.originalText)
                .setRequiredRange(1, 1500)
                .build();

        Modal modal = Modal.create("ticket:staff:modal:" + sessionId, "Edit Staff Message")
                .addComponents(Label.of("Message Content", body))
                .build();

        interaction.replyModal(modal).queue();
    }

    private void handleStaffModalSubmit(ModalInteraction interaction) {
        String sessionId = interaction.getModalId().substring("ticket:staff:modal:".length());
        PendingStaffMessage pending = pendingMessages.get(sessionId);

        if (pending == null) {
            interaction.reply("\u274C This session has expired.").setEphemeral(true).queue();
            return;
        }

        String newContent = interaction.getValue("body").getAsString();
        interaction.deferEdit().queue(); // We will re-send the verification embed

        // Re-initiate verification with new content
        TextChannel channel = interaction.getChannel().asTextChannel();
        initiateStaffVerification(pending.ticket, newContent, pending.attachments, pending.staffName, channel);

        // Remove old pending session as a new one is created in
        // initiateStaffVerification
        pendingMessages.remove(sessionId);
    }

    private void sendStaffRelayToClient(TicketEntity ticket, String content, String staffName,
            List<Message.Attachment> attachments) {
        EmbedBuilder userEmbed = new EmbedBuilder()
                .setTitle("\uD83D\uDCE9 Whip Client Support \u2014 Staff Message")
                .setColor(Color.decode("#3498db"))
                .setDescription(content)
                .setFooter("Our team is here to help! \u2022 Response by " + staffName);

        main.getJda().retrieveUserById(ticket.getUserDiscordId()).queue(user -> {
            user.openPrivateChannel().queue(pc -> {
                if (!attachments.isEmpty()) {
                    List<CompletableFuture<FileUpload>> futures = new ArrayList<>();
                    for (Message.Attachment attachment : attachments) {
                        futures.add(attachment.getProxy().download()
                                .thenApply(is -> FileUpload.fromData(is, attachment.getFileName())));
                    }
                    CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).thenAccept(v -> {
                        List<FileUpload> uploads = futures.stream().map(CompletableFuture::join).toList();
                        pc.sendFiles(uploads).addEmbeds(userEmbed.build()).queue();
                    });
                } else {
                    pc.sendMessageEmbeds(userEmbed.build()).queue();
                }
            });
        });
    }

    private void handleUserMessage(MessageReceivedEvent event) {
        main.getTicketManager().findByUserDiscordId(event.getAuthor().getId()).ifPresent(ticket -> {
            String content = event.getMessage().getContentRaw();

            if (content.startsWith("!"))
                return;

            List<Message.Attachment> attachments = event.getMessage().getAttachments();

            // Le client vient de répondre -> on attend de nouveau le staff.
            // On réinitialise l'horloge d'activité et l'étape de relance pour que
            // les rappels 1h/12h/24h repartent à partir de ce message.
            ticket.setAwaitingUserReply(false);
            ticket.setLastActivity(Instant.now());
            ticket.setStaffReminderStage(0);
            main.getTicketManager().save(ticket);

            // Log to database
            TicketMessage msg = new TicketMessage(
                    ticket.getUserDiscordId(),
                    event.getAuthor().getId(),
                    event.getAuthor().getName(),
                    false,
                    content);
            main.getTicketMessageManager().save(msg);

            // Si le message contient un fichier : on ne traduit pas, on transmet tel quel.
            if (!attachments.isEmpty()) {
                relayUserMessageToStaff(ticket, event.getAuthor().getName(), content,
                        ticket.getDetectedLanguage(), null, attachments, event.getMessage());
                return;
            }

            // 1. Detect language
            detectLanguage(content).thenAccept(detectedLang -> {
                // Update ticket language if different
                if (ticket.getDetectedLanguage() == null
                        || !ticket.getDetectedLanguage().equalsIgnoreCase(detectedLang)) {
                    ticket.setDetectedLanguage(detectedLang);
                    main.getTicketManager().save(ticket);
                }

                // 2. Translate to French for staff (if not already French)
                if (detectedLang.equalsIgnoreCase("French")) {
                    relayUserMessageToStaff(ticket, event.getAuthor().getName(), content, detectedLang, null,
                            event.getMessage().getAttachments(), event.getMessage());
                } else {
                    translate(content, "French").thenAccept(translatedText -> {
                        relayUserMessageToStaff(ticket, event.getAuthor().getName(), content, detectedLang,
                                translatedText, event.getMessage().getAttachments(), event.getMessage());
                    });
                }
            });
        });
    }

    private void relayUserMessageToStaff(TicketEntity ticket, String userName, String originalContent, String lang,
            String translation, List<Message.Attachment> attachments, Message originalUserMessage) {
        EmbedBuilder staffEmbed = new EmbedBuilder()
                .setTitle("\uD83D\uDCE9 Message from " + userName)
                .setColor(Color.decode("#5865F2"))
                .setTimestamp(Instant.now());

        if (translation != null) {
            staffEmbed.setDescription("**Original (" + lang + "):**\n" + originalContent
                    + "\n\n**Traduction (Français):**\n" + translation);
        } else {
            staffEmbed.setDescription(
                    originalContent == null || originalContent.isBlank()
                            ? "*(Aucun texte — voir la pièce jointe)*"
                            : originalContent);
            if (lang != null && !lang.isBlank()) {
                staffEmbed.setFooter("Language: " + lang);
            }
        }

        TextChannel staffChannel = main.getJda().getTextChannelById(ticket.getStaffChannelId());
        if (staffChannel != null) {
            if (!attachments.isEmpty()) {
                List<CompletableFuture<FileUpload>> futures = new ArrayList<>();
                for (Message.Attachment attachment : attachments) {
                    futures.add(attachment.getProxy().download()
                            .thenApply(is -> FileUpload.fromData(is, attachment.getFileName())));
                }
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).thenAccept(v -> {
                    List<FileUpload> uploads = futures.stream().map(CompletableFuture::join).toList();
                    staffChannel.sendFiles(uploads).addEmbeds(staffEmbed.build()).queue(m -> {
                        originalUserMessage.addReaction(Emoji.fromUnicode("\u2705")).queue(null, t -> {
                        });
                    });
                });
            } else {
                staffChannel.sendMessageEmbeds(staffEmbed.build()).queue(m -> {
                    originalUserMessage.addReaction(Emoji.fromUnicode("\u2705")).queue(null, t -> {
                    });
                });
            }
        }
    }

    private CompletableFuture<String> translate(String text, String targetLanguage) {
        if (text == null || text.isBlank())
            return CompletableFuture.completedFuture(text);

        ConfigData config = main.getConfigHandler().getPrototypeConfig(BotConfigLoader.class);
        String prompt = config.translationPrompt().replace("{targetLanguage}", targetLanguage);

        return callOpenAI(prompt, text, text);
    }

    private CompletableFuture<String> detectLanguage(String text) {
        if (text == null || text.isBlank())
            return CompletableFuture.completedFuture("French");

        ConfigData config = main.getConfigHandler().getPrototypeConfig(BotConfigLoader.class);
        String prompt = config.languageDetectionPrompt();

        return callOpenAI(prompt, text, "French");
    }

    private CompletableFuture<String> callOpenAI(String systemPrompt, String userContent, String fallback) {
        String apiKey = main.getConfigHandler().<ConfigData>getPrototypeConfig(BotConfigLoader.class).openaiApiKey();

        if (apiKey == null || apiKey.isEmpty()) {
            LOGGER.error("OpenAI API key is missing in config");
            return CompletableFuture.completedFuture(fallback);
        }

        String body;
        try {
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode root = mapper.createObjectNode();
            root.put("model", "gpt-4o-mini");
            ArrayNode messages = root.putArray("messages");
            messages.addObject().put("role", "system").put("content", systemPrompt);
            messages.addObject().put("role", "user").put("content", userContent);
            body = mapper.writeValueAsString(root);
        } catch (Exception e) {
            LOGGER.error("Failed to build OpenAI request", e);
            return CompletableFuture.completedFuture(fallback);
        }

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("https://api.openai.com/v1/chat/completions"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        return HTTP_CLIENT.sendAsync(req, HttpResponse.BodyHandlers.ofString())
                .thenApply(resp -> {
                    if (resp.statusCode() != 200) {
                        LOGGER.warn("OpenAI returned HTTP {}: {}", resp.statusCode(), resp.body());
                        return fallback;
                    }
                    try {
                        JsonNode root = new ObjectMapper().readTree(resp.body());
                        String result = root.path("choices").get(0).path("message").path("content").asText(fallback)
                                .trim();

                        main.getDashboardManager().incrementTranslations();

                        return result;
                    } catch (Exception e) {
                        LOGGER.error("Failed to parse OpenAI response", e);
                        return fallback;
                    }
                }).exceptionally(ex -> {
                    LOGGER.error("OpenAI request failed", ex);
                    return fallback;
                });
    }

    @EventHandler
    public void onMessageReactionAdd(MessageReactionAddEvent event) {
        if (event.getChannelType() != ChannelType.PRIVATE)
            return;
        if (event.getUser() == null || event.getUser().isBot())
            return;
        if (!"🗑️".equals(event.getReaction().getEmoji().getFormatted()))
            return;

        long selfId = event.getJDA().getSelfUser().getIdLong();
        event.getChannel().getIterableHistory().takeAsync(100).thenAccept(messages -> {
            for (Message msg : messages) {
                if (msg.getAuthor().getIdLong() == selfId) {
                    msg.delete().queue(null, t -> {
                    });
                }
            }
        }).exceptionally(ex -> {
            LOGGER.error("Failed to clean up DM messages after trash reaction", ex);
            return null;
        });
    }

    private static class PendingStaffMessage {
        final TicketEntity ticket;
        final String originalText;
        final String translatedText;
        final String targetLang;
        final List<Message.Attachment> attachments;
        final String staffName;

        PendingStaffMessage(TicketEntity ticket, String originalText, String translatedText, String targetLang,
                List<Message.Attachment> attachments, String staffName) {
            this.ticket = ticket;
            this.originalText = originalText;
            this.translatedText = translatedText;
            this.targetLang = targetLang;
            this.attachments = attachments;
            this.staffName = staffName;
        }
    }

}
