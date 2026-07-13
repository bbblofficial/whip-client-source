import prisma from "./prisma";

export type SyncEntity = "user" | "product" | "license" | "machine" | "download" | "session";
export type SyncAction = "create" | "update" | "delete" | "close" | "crash";

export async function notifySync(entity: SyncEntity, action: SyncAction, id?: string) {
    try {
        const payload = JSON.stringify({ entity, action, id: id ?? null });
        await prisma.$executeRaw`SELECT pg_notify('whip_sync', ${payload})`;
    } catch (error) {
        console.error("[Sync] Notification failed:", error);
    }
}
