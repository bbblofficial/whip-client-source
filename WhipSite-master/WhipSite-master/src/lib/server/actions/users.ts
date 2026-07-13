"use server";

import { revalidatePath } from "next/cache";
import prisma from "@/lib/server/prisma";
import { notifySync } from "@/lib/server/sync";
import { requireAdmin } from "@/lib/server/auth";
import bcrypt from "bcrypt";
import { z } from "zod";

const userSchema = z.object({
    username: z.string().min(3),
    password: z.string().min(6).optional(),
    discord_id: z.string().optional().nullable(),
    grade: z.enum(["user", "media", "moderator", "admin", "owner"]).optional(),
});

export async function getUsers() {
    await requireAdmin();
    return await prisma.user.findMany({
        orderBy: { created_at: "desc" },
        include: {
            _count: {
                select: { licenses: true, machines: true }
            }
        }
    });
}

export async function createUser(formData: FormData) {
    await requireAdmin();
    const username = formData.get("username") as string;
    const password = formData.get("password") as string;
    const discord_id = formData.get("discord_id") as string || null;
    const grade = (formData.get("grade") as string) || "user";

    const result = userSchema.parse({ username, password, discord_id, grade });

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await prisma.user.create({
        data: {
            username,
            password_hash: hashedPassword,
            discord_id,
            grade: grade as any,
        },
    });

    await notifySync("user", "create", user.id);
    revalidatePath("/admin/users");
}

export async function updateUser(id: String, formData: FormData) {
    await requireAdmin();
    const username = formData.get("username") as string;
    const password = formData.get("password") as string;
    const discord_id = formData.get("discord_id") as string || null;
    const grade = formData.get("grade") as string;

    const data: any = { username, discord_id };
    if (password) {
        data.password_hash = await bcrypt.hash(password, 12);
    }
    if (grade) {
        data.grade = grade;
    }

    await prisma.user.update({
        where: { id: id as string },
        data,
    });

    await notifySync("user", "update", id as string);
    revalidatePath("/admin/users");
}

export async function deleteUser(id: string) {
    await requireAdmin();
    // The DB is Flyway-managed, so its real FK actions don't necessarily
    // match the Cascade/SetNull declared in schema.prisma — a plain
    // user.delete() gets blocked by licenses/machines still referencing
    // the user. Tear the dependents down explicitly in a transaction so
    // the delete works regardless of the DB-level constraints.
    await prisma.$transaction(async (tx) => {
        // Sessions hang off both licenses and machines — kill them first.
        await tx.session.deleteMany({
            where: {
                OR: [
                    { license: { user_id: id } },
                    { machine: { user_id: id } },
                ],
            },
        });
        await tx.license.deleteMany({ where: { user_id: id } });
        await tx.machine.deleteMany({ where: { user_id: id } });
        await tx.download.deleteMany({ where: { user_id: id } });
        await tx.downloadId.deleteMany({ where: { user_id: id } });
        await tx.blacklist.deleteMany({ where: { user_id: id } });
        await tx.userConfig.deleteMany({ where: { user_id: id } });
        await tx.auditLog.deleteMany({ where: { admin_id: id } });
        await tx.user.delete({ where: { id } });
    });
    await notifySync("user", "delete", id);
    revalidatePath("/admin/users");
}
