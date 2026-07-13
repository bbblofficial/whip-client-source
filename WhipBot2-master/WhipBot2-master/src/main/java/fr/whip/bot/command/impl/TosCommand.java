package fr.whip.bot.command.impl;

import net.dv8tion.jda.api.EmbedBuilder;

import java.awt.Color;

public class TosCommand {

    public static EmbedBuilder buildEmbed() {
        return new EmbedBuilder()
                .setTitle("📋 Terms of Service — Whip Client")
                .setThumbnail(
                        "https://cdn.discordapp.com/attachments/1158906047436689458/1158906067598708837/whip_client_logo.png")
                .setColor(Color.decode("#00b0f0"))
                .setDescription(
                        "By purchasing the Whip Client, you acknowledge and accept the following terms.\n\n" +
                        "**🔒 Data Collection**\n" +
                        "For security purposes, Whip collects the following information:\n\n" +
                        "> • **License username**\n" +
                        "> • **Minecraft UUID**\n" +
                        "> • **IP address**\n" +
                        "> • **HWID** (Hardware ID)\n" +
                        "> • **Discord ID** *(not the token)*\n" +
                        "> • **PC Name**\n" +
                        "> • **Executable path**\n" +
                        "> • **Screenshot**\n\n" +
                        "This data is used exclusively for license verification and anti-cheat security purposes. " +
                        "It will never be shared with third parties.")
                .setFooter("Whip Client — By purchasing, you agree to these terms.");
    }
}
