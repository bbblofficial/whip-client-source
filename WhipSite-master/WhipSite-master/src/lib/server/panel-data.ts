// ════════════════════════════════════════════════════════════════════
//  WhipSite · panel data loader (server-only)
//  Fetches every dataset the admin panel needs in one place, with the
//  exact includes the mappers expect, and returns client-ready domain
//  objects. Consumed by the (panel) layout server component.
// ════════════════════════════════════════════════════════════════════
import "server-only";
import prisma from "@/lib/server/prisma";
import {
  mapAudit,
  mapBlacklist,
  mapConfig,
  mapDownload,
  mapLicense,
  mapMachine,
  mapProduct,
  mapSession,
  mapUser,
} from "@/lib/server/mappers";
import type {
  AuditEntry,
  BlacklistEntry,
  Config,
  Download,
  License,
  Machine,
  Product,
  Session,
  User,
} from "@/lib/types";

export interface PanelData {
  licenses: License[];
  users: User[];
  machines: Machine[];
  sessions: Session[];
  downloads: Download[];
  configs: Config[];
  blacklist: BlacklistEntry[];
  audit: AuditEntry[];
  products: Product[];
}

const EMPTY: PanelData = {
  licenses: [],
  users: [],
  machines: [],
  sessions: [],
  downloads: [],
  configs: [],
  blacklist: [],
  audit: [],
  products: [],
};

export async function getPanelData(): Promise<PanelData> {
  try {
    const [licenses, users, sessions, downloads, configs, blacklist, audit, products] = await Promise.all([
      prisma.license.findMany({
        orderBy: { created_at: "desc" },
        include: {
          user: { select: { username: true } },
          product: { select: { name: true, code: true } },
          _count: { select: { sessions: true } },
        },
      }),
      prisma.user.findMany({
        orderBy: { created_at: "desc" },
        include: { _count: { select: { licenses: true, machines: true } } },
      }),
      prisma.session.findMany({
        orderBy: { started_at: "desc" },
        take: 1000,
        include: {
          license: {
            include: {
              user: { select: { username: true } },
              product: { select: { name: true, code: true } },
            },
          },
          machine: { select: { pc_name: true } },
        },
      }),
      prisma.download.findMany({
        orderBy: { downloaded_at: "desc" },
        take: 1000,
        include: {
          user: { select: { username: true } },
          product: { select: { name: true, code: true } },
        },
      }),
      prisma.config.findMany({
        orderBy: { created_at: "desc" },
        include: { user_configs: { include: { user: { select: { username: true } } } } },
      }),
      prisma.blacklist.findMany({
        orderBy: { created_at: "desc" },
        include: { user: { select: { username: true } } },
      }),
      prisma.auditLog.findMany({
        orderBy: { created_at: "desc" },
        take: 1000,
        include: { admin: { select: { username: true } } },
      }),
      prisma.product.findMany({ orderBy: { created_at: "desc" } }),
    ]);

    // Machines fetched separately: new hw columns may not exist yet on the VPS.
    // If the query fails (column missing), fall back to a raw select of known-good columns.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let machines: any[] = [];
    try {
      machines = await prisma.machine.findMany({
        orderBy: { last_seen_at: "desc" },
        include: { user: { select: { username: true } } },
      });
    } catch {
      try {
        type RawRow = { id: string; user_id: string; hwid: string; pc_name: string; os: string; gpu_name: string | null; cpu_brand: string | null; ram_hex: string | null; last_seen_at: Date; revoked_at: Date | null; created_at: Date; username: string | null };
        const rows = await prisma.$queryRaw<RawRow[]>`
          SELECT m.id, m.user_id, m.hwid, m.pc_name, m.os,
                 m.gpu_name, m.cpu_brand, m.ram_hex,
                 m.last_seen_at, m.revoked_at, m.created_at,
                 u.username
          FROM machines m
          LEFT JOIN users u ON u.id = m.user_id
          ORDER BY m.last_seen_at DESC`;
        machines = rows.map((r) => ({
          ...r,
          board_model: null, screen_info: null, storage_info: null,
          user: r.username ? { username: r.username } : null,
        }));
      } catch (e2) {
        console.error("machines fallback query failed:", e2);
      }
    }

    // machine.user_id → most-recent license_key of that user (machines aren't
    // linked to a license directly, so we resolve via the owning user).
    const licenseKeyByUser = new Map<string, string>();
    for (const l of licenses) {
      if (l.user_id && !licenseKeyByUser.has(l.user_id)) licenseKeyByUser.set(l.user_id, l.license_key);
    }
    // Option A: derive User.lastSeen from the user's latest machine activity.
    const lastSeenByUser = new Map<string, Date>();
    for (const m of machines) {
      const prev = lastSeenByUser.get(m.user_id);
      if (!prev || m.last_seen_at > prev) lastSeenByUser.set(m.user_id, m.last_seen_at);
    }

    // user_id → username, to attribute audit events whose entity_id is a user
    // (auth, download…) to that user instead of "Système".
    const userNames = new Map<string, string>();
    for (const u of users) userNames.set(u.id, u.username);

    // audit_logs.ip is read via raw SQL so the panel never breaks if the column
    // doesn't exist yet (it's created by the server's Hibernate ddl-auto).
    const auditIps = new Map<string, string>();
    try {
      const rows = await prisma.$queryRaw<{ id: string; ip: string | null }[]>`SELECT id, ip FROM audit_logs ORDER BY created_at DESC LIMIT 1000`;
      for (const r of rows) if (r.ip) auditIps.set(r.id, r.ip);
    } catch {
      // ip column not present yet — leave IPs blank.
    }

    return {
      licenses: licenses.map(mapLicense),
      users: users.map((u) => mapUser(u, lastSeenByUser.get(u.id))),
      machines: machines.map((m) => mapMachine(m, licenseKeyByUser.get(m.user_id) ?? "")),
      sessions: sessions.map(mapSession),
      downloads: downloads.map(mapDownload),
      configs: configs.map(mapConfig),
      blacklist: blacklist.map(mapBlacklist),
      audit: audit.map((a) => mapAudit(a, userNames, auditIps)),
      products: products.map(mapProduct),
    };
  } catch (err) {
    // DB unreachable / not migrated yet — render an empty (but functional)
    // panel instead of a 500 so the UI stays browsable.
    console.error("getPanelData failed:", err);
    return EMPTY;
  }
}
