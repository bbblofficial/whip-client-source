"use server";

import { revalidatePath } from "next/cache";
import prisma from "@/lib/server/prisma";
import { requireAdmin } from "@/lib/server/auth";
import { notifySync } from "@/lib/server/sync";

export async function getSessions() {
    await requireAdmin();
    return await prisma.session.findMany({
        orderBy: { started_at: "desc" },
        include: {
            license: {
                include: {
                    user: { select: { username: true } },
                    product: { select: { name: true } }
                }
            },
            machine: { select: { pc_name: true, hwid: true } }
        }
    });
}

/**
 * Subset of session fields safe for live polling. The /admin/sessions
 * page hits this every 5 s — we don't want to ship the full include
 * graph each tick. Returns active sessions first.
 */
export async function getActiveSessions() {
    await requireAdmin();
    return await prisma.session.findMany({
        where: { ended_at: null },
        orderBy: { last_heartbeat_at: "desc" },
        select: {
            id: true,
            started_at: true,
            last_heartbeat_at: true,
            expires_at: true,
            ip: true,
            license: {
                select: {
                    license_key: true,
                    user: { select: { username: true, discord_id: true } },
                    product: { select: { name: true, code: true } },
                },
            },
            machine: { select: { pc_name: true, hwid: true } },
        },
    });
}

/**
 * Close a session: mark ended_at in DB AND broadcast pg_notify so the
 * WhipServer SyncListener kicks the live Netty channel immediately.
 * Without the notify the user would stay connected until their next
 * heartbeat timed out (60 s).
 */
export async function closeSession(id: string) {
    await requireAdmin();
    await prisma.session.update({
        where: { id },
        data: { ended_at: new Date() },
    });
    await notifySync("session", "close", id);
    revalidatePath("/admin/sessions");
}

export async function deleteSession(id: string) {
    await requireAdmin();
    // Best-effort: try to live-kick first, then drop the row. If kick
    // fails (already disconnected), delete still succeeds.
    await notifySync("session", "close", id);
    await prisma.session.delete({
        where: { id },
    });
    revalidatePath("/admin/sessions");
}

/**
 * Remote-crash a session: pg_notify the WhipServer SyncListener which
 * dispatches a SESSION_CRASH WhipNexus packet to the live DLL → DLL
 * deliberately AVs → host game process dies. The DB session row is
 * marked ended_at so it doesn't reappear in the live list.
 *
 * Use sparingly — this is the nuclear option. Cheat detection is
 * usually a better fit for blacklisting; crash is for when an admin
 * wants the user gone NOW.
 */
export async function crashSession(id: string) {
    await requireAdmin();
    await prisma.session.update({
        where: { id },
        data: { ended_at: new Date() },
    });
    await notifySync("session", "crash", id);
    revalidatePath("/admin/sessions");
}
