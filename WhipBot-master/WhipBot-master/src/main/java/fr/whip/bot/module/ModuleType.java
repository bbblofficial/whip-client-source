package fr.whip.bot.module;

public enum ModuleType {
    ;

    private final Class<? extends IModule> moduleClass;

    ModuleType(Class<? extends IModule> moduleClass) {
        this.moduleClass = moduleClass;
    }

    public IModule create() throws Exception {
        return this.moduleClass.getDeclaredConstructor().newInstance();
    }
}
