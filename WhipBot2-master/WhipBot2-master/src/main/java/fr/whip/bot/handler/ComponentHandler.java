package fr.whip.bot.handler;

import net.dv8tion.jda.api.events.interaction.component.GenericComponentInteractionCreateEvent;
import net.dv8tion.jda.api.interactions.components.ComponentInteraction;
import net.dv8tion.jda.api.interactions.modals.ModalInteraction;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class ComponentHandler {

    private final Map<String, Consumer<ComponentInteraction>> components;
    private final Map<String, Consumer<ModalInteraction>> modals;

    public ComponentHandler() {
        this.components = new HashMap<>();
        this.modals = new HashMap<>();
    }

    public void register(String id, Consumer<ComponentInteraction> component) {
        if (this.components.containsKey(id)) {
            return;
        }
        this.components.put(id, component);
    }

    public void registerModal(String id, Consumer<ModalInteraction> modal) {
        if (this.modals.containsKey(id)) {
            return;
        }
        this.modals.put(id, modal);
    }

    public void unregister(String id) {
        this.components.remove(id);
        this.modals.remove(id);
    }

    public void unregister(String... ids) {
        for (String id : ids) {
            unregister(id);
        }
    }

    public void applyInteraction(GenericComponentInteractionCreateEvent event) {
        String id = event.getComponentId();
        Consumer<ComponentInteraction> consumer = getComponent(id);

        if (consumer == null) {
            // Try prefix matching (e.g., "id:subid" matches "id:")
            for (Map.Entry<String, Consumer<ComponentInteraction>> entry : components.entrySet()) {
                if (id.startsWith(entry.getKey()) && entry.getKey().endsWith(":")) {
                    consumer = entry.getValue();
                    break;
                }
            }
        }

        if (consumer == null) {
            return;
        }
        consumer.accept(event);
    }

    public void applyModalInteraction(ModalInteraction event) {
        String id = event.getModalId();
        Consumer<ModalInteraction> consumer = getModal(id);

        if (consumer == null) {
            // Try prefix matching
            for (Map.Entry<String, Consumer<ModalInteraction>> entry : modals.entrySet()) {
                if (id.startsWith(entry.getKey()) && entry.getKey().endsWith(":")) {
                    consumer = entry.getValue();
                    break;
                }
            }
        }

        if (consumer == null) {
            return;
        }
        consumer.accept(event);
    }

    public Consumer<ComponentInteraction> getComponent(String id) {
        return this.components.get(id);
    }

    public Consumer<ModalInteraction> getModal(String id) {
        return this.modals.get(id);
    }
}
