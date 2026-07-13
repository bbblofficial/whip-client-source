"use server";

import { revalidatePath } from "next/cache";
import prisma from "@/lib/server/prisma";
import { notifySync } from "@/lib/server/sync";
import { requireAdmin } from "@/lib/server/auth";

export async function getDownloads() {
    await requireAdmin();
    return await prisma.download.findMany({
        orderBy: { downloaded_at: "desc" },
        include: {
            user: { select: { username: true } },
            product: { select: { name: true } }
        }
    });
}

export async function deleteDownload(id: string) {
    await requireAdmin();
    await prisma.download.delete({
        where: { id },
    });
    await notifySync("download", "delete", id);
    revalidatePath("/admin/downloads");
}

export async function revokeDownload(id: string, reason: string) {
    await requireAdmin();
    await prisma.download.update({
        where: { id },
        data: { revoked: true, revoke_reason: reason || null },
    });
    await notifySync("download", "update", id);
    revalidatePath("/admin/downloads");
}

export async function unrevokeDownload(id: string) {
    await requireAdmin();
    await prisma.download.update({
        where: { id },
        data: { revoked: false },
    });
    await notifySync("download", "update", id);
    revalidatePath("/admin/downloads");
}

export async function createDownload(userId: string, productId: string | null) {
    await requireAdmin();
    const { randomBytes } = await import("crypto");
    const downloadId = randomBytes(16).toString("hex");
    const record = await prisma.download.create({
        data: {
            download_id: downloadId,
            user_id: userId,
            product_id: productId || null,
            downloaded_at: new Date(),
            revoked: false,
        },
    });
    await notifySync("download", "create", record.id);
    revalidatePath("/admin/downloads");
    return { id: record.id, downloadId };
}
