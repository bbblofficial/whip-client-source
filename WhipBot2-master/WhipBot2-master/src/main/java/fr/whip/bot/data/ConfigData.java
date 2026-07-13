package fr.whip.bot.data;

import java.io.File;

public record ConfigData(
        String token,
        DatabaseData database,
        File loaderPath,
        FileHostingData fileHosting,
        ChannelsData channels,
        PermissionsData permissions,
        String openaiApiKey,
        String translationPrompt,
        String languageDetectionPrompt) {

    public ConfigData {
        if (database == null) {
            database = new DatabaseData("localhost", 5432, "whip", "whip", "");
        }
        if (fileHosting == null) {
            fileHosting = new FileHostingData(true, 8080, "http://localhost:8080");
        }
        if (channels == null) {
            channels = new ChannelsData("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "");
        }
        if (permissions == null) {
            permissions = new PermissionsData("", java.util.List.of(), "", "", "");
        }
        if (openaiApiKey == null) {
            openaiApiKey = "";
        }
        if (translationPrompt == null || translationPrompt.isEmpty()) {
            translationPrompt = "Translate the following text to {targetLanguage}. Return only the translated text, nothing else.";
        }
        if (languageDetectionPrompt == null || languageDetectionPrompt.isEmpty()) {
            languageDetectionPrompt = "Detect the language of the following text. Reply with only the language name in English (e.g. French, Spanish, German, English). Nothing else.";
        }
    }
}
