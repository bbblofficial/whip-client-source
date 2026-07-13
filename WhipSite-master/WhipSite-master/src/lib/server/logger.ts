import prisma from "@/lib/server/prisma";

/**
 * Write an audit-log row. For an admin action pass the admin id + the target
 * entity uuid. For a SYSTEM event (startup, connection, error…) pass null for
 * both — the journal treats "admin_id == null && entity_id == null" as system.
 * Never throws (logging must not break the caller).
 */
export async function logAction(
  adminId: string | null,
  action: string,
  entity: string,
  entityId?: string | null,
  details?: string,
) {
  try {
    await prisma.auditLog.create({
      data: {
        admin_id: adminId ?? null,
        action,
        entity,
        entity_id: entityId ?? null,
        details,
      },
    });
  } catch (error) {
    console.error("Failed to log action:", error);
  }
}

/** Convenience wrapper for system events (no admin, no entity). */
export async function logSystem(action: string, entity: string, details?: string) {
  await logAction(null, action, entity, null, details);
}
