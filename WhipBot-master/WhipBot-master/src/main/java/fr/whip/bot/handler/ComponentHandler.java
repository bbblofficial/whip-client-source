package fr.whip.bot.handler;

import net.dv8tion.jda.api.events.interaction.component.GenericComponentInteractionCreateEvent;
import net.dv8tion.jda.api.interactions.components.ComponentInteraction;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class ComponentHandler {

    private final Map<String, Consumer<ComponentInteraction>> components;

    public ComponentHandler() {
        this.components = new HashMap<>();
    }

    public void register(String id, Consumer<ComponentInteraction> component) {
        if (this.components.containsKey(id)) {
            return;
        }
        this.components.put(id, component);
    }

    public void unregister(String id) {
        this.components.remove(id);
    }

    public void unregister(String... ids) {
        for (String id : ids) {
            unregister(id);
        }
    }

    public void applyInteraction(GenericComponentInteractionCreateEvent event) {
        Consumer<ComponentInteraction> consumer = getComponent(event.getComponentId());
        if (consumer == null) {
            return;
        }
        consumer.accept(event);
    }

    public Consumer<ComponentInteraction> getComponent(String id) {
        return this.components.get(id);
    }
}
