package fr.whip.bot.tmp;

public class Probe {
    public static void main(String[] args) {
        try {
            String[] commonTerms = { "label", "title", "text", "name", "content" };
            Class<?> tiClass = Class.forName("net.dv8tion.jda.api.components.textinput.TextInput");
            System.out.println("Searching terms in TextInput:");
            for (java.lang.reflect.Method m : tiClass.getMethods()) {
                for (String term : commonTerms) {
                    if (m.getName().toLowerCase().contains(term)) {
                        System.out.println("- Method: " + m.getName() + " (" + m.getParameterCount() + " args)");
                        break;
                    }
                }
            }

            Class<?> builderClass = Class.forName("net.dv8tion.jda.api.components.textinput.TextInput$Builder");
            System.out.println("\nSearching terms in TextInput.Builder:");
            for (java.lang.reflect.Method m : builderClass.getMethods()) {
                for (String term : commonTerms) {
                    if (m.getName().toLowerCase().contains(term)) {
                        System.out.println("- Method: " + m.getName() + " (" + m.getParameterCount() + " args)");
                        break;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
