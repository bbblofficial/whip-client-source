package fr.whip.bot.command.impl;

import fr.whip.api.model.Product;
import fr.whip.api.model.ProductType;
import fr.whip.bot.command.base.ParentComplexBaseCommand;
import fr.whip.bot.manager.impl.ProductManager;
import fr.whip.bot.util.OptionUtils;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.interactions.commands.OptionType;
import net.dv8tion.jda.api.interactions.commands.build.OptionData;

import java.awt.*;
import java.util.Optional;

public class ProductCommand extends ParentComplexBaseCommand {

    public ProductCommand(ProductManager productManager) {
        registerChildCommand("create", "Create a new product", event -> {
            if (!event.getMember().hasPermission(Permission.ADMINISTRATOR)) {
                event.reply("You don't have permission to use this command.").setEphemeral(true).queue();
                return;
            }

            String codeStr = OptionUtils.getStringOption(event, "code").orElseThrow();
            String name = OptionUtils.getStringOption(event, "name").orElseThrow();
            String description = OptionUtils.getStringOption(event, "description").orElse(null);

            ProductType code;
            try {
                code = ProductType.valueOf(codeStr);
            } catch (IllegalArgumentException e) {
                event.reply("Invalid product code: " + codeStr).setEphemeral(true).queue();
                return;
            }

            if (productManager.findByCode(code).isPresent()) {
                event.reply("Product already exists: " + code.getDisplayName()).setEphemeral(true).queue();
                return;
            }

            Product product = new Product();
            product.setCode(code);
            product.setName(name);
            product.setDescription(description);

            productManager.save(product);

            EmbedBuilder embed = new EmbedBuilder()
                    .setTitle("Product Created")
                    .setColor(Color.GREEN)
                    .addField("Name", product.getName(), true)
                    .addField("Code", product.getCode().name(), true);

            if (description != null) {
                embed.addField("Description", description, false);
            }

            event.replyEmbeds(embed.build()).setEphemeral(true).queue();
        }, Optional.of(data -> data
                .addOptions(buildProductTypeOption("code", "The product code", true))
                .addOption(OptionType.STRING, "name", "The product name", true)
                .addOption(OptionType.STRING, "description", "Product description", false)));

        registerChildCommand("delete", "Delete a product", event -> {
            if (!event.getMember().hasPermission(Permission.ADMINISTRATOR)) {
                event.reply("You don't have permission to use this command.").setEphemeral(true).queue();
                return;
            }

            String codeStr = OptionUtils.getStringOption(event, "code").orElseThrow();

            ProductType code;
            try {
                code = ProductType.valueOf(codeStr);
            } catch (IllegalArgumentException e) {
                event.reply("Invalid product code: " + codeStr).setEphemeral(true).queue();
                return;
            }

            productManager.findByCode(code).ifPresentOrElse(product -> {
                productManager.delete(product.getId());
                event.reply("Product `" + product.getName() + "` has been deleted.").setEphemeral(true).queue();
            }, () -> event.reply("Product not found.").setEphemeral(true).queue());
        }, Optional.of(data -> data
                .addOptions(buildProductTypeOption("code", "The product to delete", true))));

        registerChildCommand("list", "List all products", event -> {
            var products = productManager.findAll();

            if (products.isEmpty()) {
                event.reply("No products found.").setEphemeral(true).queue();
                return;
            }

            EmbedBuilder embed = new EmbedBuilder()
                    .setTitle("Products")
                    .setColor(Color.BLUE);

            for (Product product : products) {
                String desc = product.getDescription() != null ? product.getDescription() : "No description";
                embed.addField(product.getName(), "Code: `" + product.getCode().name() + "`\n" + desc, false);
            }

            event.replyEmbeds(embed.build()).setEphemeral(true).queue();
        });
    }

    public static OptionData buildProductTypeOption(String name, String description, boolean required) {
        OptionData option = new OptionData(OptionType.STRING, name, description, required);
        for (ProductType type : ProductType.values()) {
            option.addChoice(type.getDisplayName(), type.name());
        }
        return option;
    }

    @Override
    public String getName() {
        return "product";
    }

    @Override
    public String getDescription() {
        return "Manage products";
    }
}