"use server";

import prisma from "@/lib/server/prisma";
import { revalidatePath } from "next/cache";
import { requireAdmin } from "@/lib/server/auth";
import { notifySync } from "@/lib/server/sync";

export async function getConfigs() {
    await requireAdmin();
    try {
        const configs = await prisma.config.findMany({
            include: {
                user_configs: {
                    include: {
                        user: true
                    }
                }
            },
            orderBy: {
                created_at: 'desc'
            }
        });
        return configs;
    } catch (error) {
        console.error("Error fetching configs:", error);
        return [];
    }
}

export async function createConfig(formData: FormData) {
    await requireAdmin();
    try {
        const name = formData.get("name") as string;
        const description = formData.get("description") as string;
        const data = formData.get("data") as string; // Expecting JSON string
        const isPublic = formData.get("is_public") === "on";
        const userId = formData.get("user_id") as string; // Owner

        // Validate JSON
        let parsedData;
        try {
            parsedData = JSON.parse(data);
        } catch (e) {
            throw new Error("Invalid JSON data");
        }

        const config = await prisma.config.create({
            data: {
                name,
                description,
                data: parsedData,
                is_public: isPublic,
                user_configs: {
                    create: {
                        user_id: userId,
                        is_owner: true
                    }
                }
            }
        });

        revalidatePath("/admin/configs");
        return { success: true, config };
    } catch (error) {
        console.error("Error creating config:", error);
        return { success: false, error: "Failed to create config" };
    }
}

export async function updateConfig(id: string, formData: FormData) {
    await requireAdmin();
    try {
        const name = formData.get("name") as string;
        const description = formData.get("description") as string;
        const data = formData.get("data") as string;
        const isPublic = formData.get("is_public") === "on";

        // Validate JSON if provided
        let parsedData;
        if (data) {
            try {
                parsedData = JSON.parse(data);
            } catch (e) {
                throw new Error("Invalid JSON data");
            }
        }

        const updateData: any = {
            name,
            description,
            is_public: isPublic,
        };

        if (parsedData) {
            updateData.data = parsedData;
        }

        await prisma.config.update({
            where: { id },
            data: updateData
        });

        // Notify every user who has this config so their live session
        // gets kicked → reconnects → fetches the new config. Without
        // this, edits stay invisible until the user reloads manually.
        const owners = await prisma.userConfig.findMany({
            where: { config_id: id },
            select: { user_id: true },
        });
        for (const o of owners) {
            await notifySync("user", "update", o.user_id);
        }

        revalidatePath("/admin/configs");
        return { success: true };
    } catch (error) {
        console.error("Error updating config:", error);
        return { success: false, error: "Failed to update config" };
    }
}

export async function deleteConfig(id: string) {
    await requireAdmin();
    try {
        await prisma.config.delete({
            where: { id }
        });

        revalidatePath("/admin/configs");
        return { success: true };
    } catch (error) {
        console.error("Error deleting config:", error);
        return { success: false, error: "Failed to delete config" };
    }
}
