package fr.whip.bot.data;

public record ChannelsData(
        String guildId,
        String customerGuildId,
        String ticketCategoryId,
        String buyTicketCategoryId,
        String questionsTicketCategoryId,
        String hwidTicketCategoryId,
        String otherTicketCategoryId,
        String suggestionChannelId,
        String bugReportChannelId,
        String downloadChannelId,
        String transcriptLogsChannelId,
        String downloadCustomerChannelId,
        String downloadBetaChannelId,
        String suggestionCustomerChannelId,
        String suggestionBetaChannelId,
        String bugReportCustomerChannelId,
        String bugReportBetaChannelId) {

    public ChannelsData {
        if (guildId == null) guildId = "";
        if (customerGuildId == null) customerGuildId = "";
        if (ticketCategoryId == null) ticketCategoryId = "";
        if (buyTicketCategoryId == null) buyTicketCategoryId = "";
        if (questionsTicketCategoryId == null) questionsTicketCategoryId = "";
        if (hwidTicketCategoryId == null) hwidTicketCategoryId = "";
        if (otherTicketCategoryId == null) otherTicketCategoryId = "";
        if (suggestionChannelId == null) suggestionChannelId = "";
        if (bugReportChannelId == null) bugReportChannelId = "";
        if (downloadChannelId == null) downloadChannelId = "";
        if (transcriptLogsChannelId == null) transcriptLogsChannelId = "";
        if (downloadCustomerChannelId == null) downloadCustomerChannelId = "";
        if (downloadBetaChannelId == null) downloadBetaChannelId = "";
        if (suggestionCustomerChannelId == null) suggestionCustomerChannelId = "";
        if (suggestionBetaChannelId == null) suggestionBetaChannelId = "";
        if (bugReportCustomerChannelId == null) bugReportCustomerChannelId = "";
        if (bugReportBetaChannelId == null) bugReportBetaChannelId = "";
    }
}
