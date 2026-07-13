package fr.whip.bot.handler;

import fr.whip.bot.WhipBot;
import fr.whip.bot.listener.EventHandler;
import fr.whip.bot.listener.Listener;
import net.dv8tion.jda.api.events.GenericEvent;
import net.dv8tion.jda.api.hooks.EventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Consumer;

public class ListenerHandler implements EventListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(ListenerHandler.class);

    private final ConcurrentMap<Class<?>, List<Consumer<GenericEvent>>> eventHandlers;
    private final ConcurrentMap<Listener, List<ConsumerEntry>> listenerConsumers;

    public ListenerHandler() {
        this.eventHandlers = new ConcurrentHashMap<>();
        this.listenerConsumers = new ConcurrentHashMap<>();
    }

    public void init(WhipBot main) {
        main.getJda().addEventListener(this);
    }

    public void register(Listener listener) {
        Class<?> clazz = listener.getClass();
        List<ConsumerEntry> consumerEntries = new ArrayList<>();

        Set<Method> allMethods = getAllMethodsFromListenerHierarchy(clazz);
        for (Method method : allMethods) {
            if (!method.isAnnotationPresent(EventHandler.class)) {
                continue;
            }

            if (method.getParameterCount() != 1) {
                LOGGER.warn(
                        "Method {} has @EventHandler but wrong parameter count: {}",
                        method.getName(),
                        method.getParameterCount());
                continue;
            }

            Class<?> eventType = method.getParameterTypes()[0];
            if (!GenericEvent.class.isAssignableFrom(eventType)) {
                LOGGER.warn(
                        "Method {} has @EventHandler but parameter is not a GenericEvent: {}",
                        method.getName(),
                        eventType.getSimpleName());
                continue;
            }

            method.setAccessible(true);

            Consumer<GenericEvent> consumer = createConsumer(listener, method, eventType);

            ConsumerEntry entry = new ConsumerEntry(eventType, consumer, method.getName());
            consumerEntries.add(entry);
            eventHandlers.computeIfAbsent(eventType, k -> new ArrayList<>()).add(consumer);
        }

        if (!consumerEntries.isEmpty()) {
            listenerConsumers.put(listener, consumerEntries);
        }
    }

    private Set<Method> getAllMethodsFromListenerHierarchy(Class<?> startClass) {
        Set<Method> methods = new LinkedHashSet<>();
        Set<String> processedClasses = new HashSet<>();
        traverseClassHierarchy(startClass, methods, processedClasses);
        return methods;
    }

    private void traverseClassHierarchy(
            Class<?> clazz, Set<Method> methods, Set<String> processedClasses) {
        if (clazz == null || clazz == Object.class) {
            return;
        }

        String className = clazz.getName();
        if (processedClasses.contains(className)) {
            return;
        }
        processedClasses.add(className);

        Method[] declaredMethods = clazz.getDeclaredMethods();
        Collections.addAll(methods, declaredMethods);

        for (Class<?> interfaceClass : clazz.getInterfaces()) {
            traverseInterfaceHierarchy(interfaceClass, methods, processedClasses);
        }

        traverseClassHierarchy(clazz.getSuperclass(), methods, processedClasses);
    }

    private void traverseInterfaceHierarchy(
            Class<?> interfaceClass, Set<Method> methods, Set<String> processedClasses) {
        if (interfaceClass == null) {
            return;
        }

        String interfaceName = interfaceClass.getName();
        if (processedClasses.contains(interfaceName)) {
            return;
        }
        processedClasses.add(interfaceName);

        Method[] declaredMethods = interfaceClass.getDeclaredMethods();
        Collections.addAll(methods, declaredMethods);
        for (Class<?> parentInterface : interfaceClass.getInterfaces()) {
            traverseInterfaceHierarchy(parentInterface, methods, processedClasses);
        }
    }

    private Consumer<GenericEvent> createConsumer(
            Listener listener, Method method, Class<?> eventType) {
        return event -> {
            try {
                method.invoke(listener, eventType.cast(event));
            } catch (Exception e) {
                LOGGER.error("Error: {}.{}", listener.getClass().getSimpleName(), method.getName(), e);
            }
        };
    }

    public void unregister(Listener listener) {
        List<ConsumerEntry> entries = listenerConsumers.remove(listener);
        if (entries == null || entries.isEmpty()) {
            return;
        }

        for (ConsumerEntry entry : entries) {
            List<Consumer<GenericEvent>> consumers = eventHandlers.get(entry.eventType);
            if (consumers == null || consumers.isEmpty()) {
                continue;
            }

            consumers.remove(entry.consumer);

            if (consumers.isEmpty()) {
                eventHandlers.remove(entry.eventType);
            }
        }
    }

    @Override
    public void onEvent(GenericEvent event) {
        Class<?> eventType = event.getClass();

        List<Consumer<GenericEvent>> handlers = eventHandlers.get(eventType);
        if (handlers != null) {
            for (Consumer<GenericEvent> handler : handlers) {
                handler.accept(event);
            }
        }
    }

    private record ConsumerEntry(
            Class<?> eventType, Consumer<GenericEvent> consumer, String methodName) {}
}
