"use server";

import { revalidatePath } from "next/cache";
import prisma from "@/lib/server/prisma";
import { notifySync } from "@/lib/server/sync";
import { requireAdmin } from "@/lib/server/auth";

export async function getBlacklist() {
    await requireAdmin();
    return await prisma.blacklist.findMany({
        orderBy: { created_at: "desc" },
        include: {
            user: { select: { username: true } },
        },
    });
}

export async function blacklistUser(userId: string, reason: string, expiresAt: string | null, createdBy: string) {
    await requireAdmin();
    const entry = await prisma.blacklist.create({
        data: {
            user_id: userId,
            reason: reason || null,
            expires_at: expiresAt ? new Date(expiresAt) : null,
            created_by: createdBy || "admin",
        },
    });
    await notifySync("user", "update", userId);
    revalidatePath("/admin/blacklist");
    return entry;
}

export async function unblacklistUser(id: string) {
    await requireAdmin();
    const entry = await prisma.blacklist.delete({
        where: { id },
    });
    await notifySync("user", "update", entry.user_id);
    revalidatePath("/admin/blacklist");
}

export async function getUsers() {
    await requireAdmin();
    return await prisma.user.findMany({
        orderBy: { username: "asc" },
        select: { id: true, username: true },
    });
}
