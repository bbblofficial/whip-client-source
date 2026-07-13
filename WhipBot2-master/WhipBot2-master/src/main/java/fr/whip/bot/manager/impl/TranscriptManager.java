package fr.whip.bot.manager.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.entity.TicketEntity;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.JDA;
import net.dv8tion.jda.api.entities.Message;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;
import net.dv8tion.jda.api.utils.FileUpload;

import java.awt.Color;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class TranscriptManager {

    public void generateAndSend(WhipBot main, JDA jda, TicketEntity ticket, String closedBy) {
        TextChannel staffChannel = jda.getTextChannelById(ticket.getStaffChannelId());
        if (staffChannel == null)
            return;

        String logsChannelId = ((ConfigData) main.getConfigHandler().getPrototypeConfig(BotConfigLoader.class))
                .channels().transcriptLogsChannelId();
        TextChannel logsChannel = jda.getTextChannelById(logsChannelId);

        if (logsChannel == null) {
            logsChannel = jda.getTextChannelsByName("logs-tickets", true).stream().findFirst().orElse(null);
        }

        if (logsChannel == null)
            return;

        final TextChannel finalLogsChannel = logsChannel;

        staffChannel.getIterableHistory().takeAsync(100).thenAccept(messages -> {
            List<Message> sortedMessages = new ArrayList<>(messages);
            Collections.reverse(sortedMessages);

            StringBuilder transcript = new StringBuilder();
            transcript.append("=== WHIP TICKET TRANSCRIPT ===\n");
            transcript.append("Ticket ID: ").append(ticket.getUserDiscordId()).append("\n");
            transcript.append("Reason: ").append(ticket.getReason()).append("\n");
            transcript.append("Opened at: ").append(ticket.getOpenedAt()).append("\n");
            transcript.append("Closed at: ").append(Instant.now()).append("\n");
            transcript.append("Closed by: ").append(closedBy).append("\n");
            transcript.append("==============================\n\n");

            for (Message msg : sortedMessages) {
                if (msg.getAuthor().isBot()) {
                    boolean isRelay = false;
                    String overrideAuthor = null;
                    if (!msg.getEmbeds().isEmpty()) {
                        for (net.dv8tion.jda.api.entities.MessageEmbed embed : msg.getEmbeds()) {
                            String title = embed.getTitle();

                            if (title != null && title.contains("Whip Client Ticket")) {
                                isRelay = false;
                                overrideAuthor = null;
                                break;
                            }

                            if (embed.getAuthor() != null) {
                                isRelay = true;
                                overrideAuthor = embed.getAuthor().getName();
                                break;
                            }

                            if (title != null) {
                                if (title.contains("Message from ")) {
                                    isRelay = true;
                                    overrideAuthor = title.substring(title.indexOf("Message from ") + "Message from ".length()).trim();
                                    break;
                                }
                                if (title.contains("Message Sent")) {
                                    isRelay = true;
                                    String footer = embed.getFooter() != null ? embed.getFooter().getText() : null;
                                    if (footer != null && footer.contains("Sent by ")) {
                                        overrideAuthor = footer.substring(footer.indexOf("Sent by ") + "Sent by ".length()).trim();
                                    } else {
                                        overrideAuthor = "Staff";
                                    }
                                    break;
                                }
                                if (title.contains("Staff Message")) {
                                    isRelay = true;
                                    String footer = embed.getFooter() != null ? embed.getFooter().getText() : null;
                                    if (footer != null && footer.contains("Response by ")) {
                                        overrideAuthor = footer.substring(footer.indexOf("Response by ") + "Response by ".length()).trim();
                                    } else {
                                        overrideAuthor = "Staff";
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    if (!isRelay)
                        continue;

                    String time = msg.getTimeCreated().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
                    String authorName = overrideAuthor != null ? overrideAuthor : msg.getAuthor().getName();

                    for (net.dv8tion.jda.api.entities.MessageEmbed embed : msg.getEmbeds()) {
                        String embedDesc = embed.getDescription();
                        if (embedDesc == null || embedDesc.isBlank())
                            continue;
                        String cleaned = cleanRelayDescription(embedDesc);
                        transcript.append("[").append(time).append("] ").append(authorName).append(": ")
                                .append(cleaned).append("\n");
                    }

                    if (!msg.getAttachments().isEmpty()) {
                        for (Message.Attachment att : msg.getAttachments()) {
                            transcript.append("[").append(time).append("] ").append(authorName)
                                    .append(" sent file: ").append(att.getFileName()).append("\n");
                        }
                    }
                    continue;
                }

                String author = msg.getAuthor().getName();
                String time = msg.getTimeCreated().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
                String content = msg.getContentRaw();

                if (!content.isEmpty()) {
                    transcript.append("[").append(time).append("] ").append(author).append(": ")
                            .append(content).append("\n");
                }

                if (!msg.getAttachments().isEmpty()) {
                    for (Message.Attachment att : msg.getAttachments()) {
                        transcript.append("[").append(time).append("] ").append(author)
                                .append(" sent file: ").append(att.getFileName()).append("\n");
                    }
                }
            }

            byte[] bytes = transcript.toString().getBytes(StandardCharsets.UTF_8);
            String fileName = "transcript-" + ticket.getUserDiscordId() + ".txt";

            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss")
                    .withZone(ZoneId.systemDefault());

            jda.retrieveUserById(ticket.getUserDiscordId()).queue(creator -> {
                String creatorName = creator != null ? creator.getName() : "Unknown";

                EmbedBuilder logEmbed = new EmbedBuilder()
                        .setTitle("📄 Ticket Transcript Archived")
                        .setColor(Color.GRAY)
                        .addField("Category", ticket.getReason(), true)
                        .addField("Creator", creatorName, true)
                        .addField("Closed By", closedBy, true)
                        .addField("Opened At", formatter.format(ticket.getOpenedAt()), false)
                        .addField("Closed At", formatter.format(Instant.now()), false)
                        .addField("User ID", ticket.getUserDiscordId(), false);

                finalLogsChannel.sendMessageEmbeds(logEmbed.build())
                        .addFiles(FileUpload.fromData(bytes, fileName))
                        .queue();
            }, throwable -> {
                EmbedBuilder logEmbed = new EmbedBuilder()
                        .setTitle("📄 Ticket Transcript Archived")
                        .setColor(Color.GRAY)
                        .addField("Category", ticket.getReason(), true)
                        .addField("Creator", "Unknown User", true)
                        .addField("Closed By", closedBy, true)
                        .addField("Opened At", formatter.format(ticket.getOpenedAt()), false)
                        .addField("Closed At", formatter.format(Instant.now()), false)
                        .addField("User ID", ticket.getUserDiscordId(), false);

                finalLogsChannel.sendMessageEmbeds(logEmbed.build())
                        .addFiles(FileUpload.fromData(bytes, fileName))
                        .queue();
            });
        });
    }

    private String cleanRelayDescription(String raw) {
        if (raw == null) return "";
        String text = raw;

        int origIdx = text.indexOf("**Original");
        if (origIdx >= 0) {
            int origStart = text.indexOf(":**\n", origIdx);
            int transIdx = text.indexOf("**Tradu", origIdx);
            if (transIdx < 0) transIdx = text.indexOf("**Translated", origIdx);
            if (origStart >= 0) {
                int end = transIdx > origStart ? transIdx : text.length();
                String original = text.substring(origStart + 4, end).trim();
                return original.replaceAll("\\s+", " ");
            }
        }

        return text.replaceAll("\\s+", " ").trim();
    }
}
