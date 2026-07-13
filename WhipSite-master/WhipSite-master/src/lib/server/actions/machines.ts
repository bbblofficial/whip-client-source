"use server";

import { revalidatePath } from "next/cache";
import prisma from "@/lib/server/prisma";
import { notifySync } from "@/lib/server/sync";
import { requireAdmin } from "@/lib/server/auth";

export async function getMachines() {
    await requireAdmin();
    return await prisma.machine.findMany({
        orderBy: { last_seen_at: "desc" },
        include: {
            user: { select: { username: true } },
            _count: { select: { sessions: true } }
        }
    });
}

export async function revokeMachine(id: string) {
    await requireAdmin();
    await prisma.machine.update({
        where: { id },
        data: { revoked_at: new Date() },
    });
    await notifySync("machine", "update", id);
    revalidatePath("/admin/machines");
}

export async function unrevokeMachine(id: string) {
    await requireAdmin();
    await prisma.machine.update({
        where: { id },
        data: { revoked_at: null },
    });
    await notifySync("machine", "update", id);
    revalidatePath("/admin/machines");
}

export async function deleteMachine(id: string) {
    await requireAdmin();
    await prisma.machine.delete({
        where: { id },
    });
    await notifySync("machine", "delete", id);
    revalidatePath("/admin/machines");
}

export async function updateMachineHwid(id: string, newHwid: string) {
    await requireAdmin();
    await prisma.machine.update({
        where: { id },
        data: { hwid: newHwid },
    });
    await notifySync("machine", "update", id);
    revalidatePath("/admin/machines");
}

export async function getMachineHistory(machineId: string) {
    await requireAdmin();
    try {
        return await prisma.machineHistory.findMany({
            where: { machine_id: machineId },
            orderBy: { changed_at: "desc" },
            take: 100,
        });
    } catch {
        return [];
    }
}
