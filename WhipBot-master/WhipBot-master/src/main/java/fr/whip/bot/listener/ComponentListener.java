package fr.whip.bot.listener;

import fr.whip.bot.WhipBot;
import net.dv8tion.jda.api.events.interaction.component.ButtonInteractionEvent;
import net.dv8tion.jda.api.events.interaction.component.GenericComponentInteractionCreateEvent;

public record ComponentListener(WhipBot main) implements Listener {

    @EventHandler
    public void onComponentInteract(GenericComponentInteractionCreateEvent event) {
        this.main.getComponentHandler().applyInteraction(event);
    }

    @EventHandler
    public void onButtonInteract(ButtonInteractionEvent event) {
        this.main.getComponentHandler().applyInteraction(event);
    }
}
