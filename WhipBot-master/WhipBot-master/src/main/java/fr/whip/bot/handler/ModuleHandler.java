package fr.whip.bot.handler;

import fr.whip.bot.WhipBot;
import fr.whip.bot.module.IModule;
import fr.whip.bot.module.ModuleType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.EnumMap;
import java.util.Map;

public class ModuleHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ModuleHandler.class);

    private final Map<ModuleType, IModule> modules;

    public ModuleHandler() {
        this.modules = new EnumMap<>(ModuleType.class);
    }

    public void init() {
        for (ModuleType type : ModuleType.values()) {
            try {
                registerModule(type.create());
            } catch (Exception e) {
                LOGGER.error("Error while initializing module {}", type.name(), e);
            }
        }
    }

    public void load(WhipBot main) {
        for (IModule module : this.modules.values()) {
            try {
                module.onLoad(main);
            } catch (Exception e) {
                LOGGER.error("Error while loading module {}", module.getId(), e);
            }
        }
    }

    public void unload(WhipBot main) {
        for (IModule module : this.modules.values()) {
            try {
                module.onUnload(main);
            } catch (Exception e) {
                LOGGER.error("Error while unloading module {}", module.getId(), e);
            }
        }
    }

    @SuppressWarnings("unchecked")
    public <T extends IModule> T getModule(ModuleType type) {
        return (T) this.modules.get(type);
    }

    public void registerModule(IModule module) {
        this.modules.put(module.getType(), module);
    }

    public void unregisterModule(ModuleType type) {
        this.modules.remove(type);
    }
}
