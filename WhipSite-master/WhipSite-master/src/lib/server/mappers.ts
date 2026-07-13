// ════════════════════════════════════════════════════════════════════
//  WhipSite · DB → client-type mappers
//  Translate the Prisma rows (snake_case, DB shapes) returned by the
//  server actions into the camelCase domain types the panel UI consumes
//  (src/lib/types.ts). Fields the DB doesn't carry yet are filled with
//  safe defaults and flagged with TODO so they're easy to find later.
// ════════════════════════════════════════════════════════════════════
import type {
  AuditCategory,
  AuditEntry,
  AuditSeverity,
  BlacklistEntry,
  Config,
  Download,
  Grade,
  License,
  LicenseStatus,
  Machine,
  ModuleSetting,
  Product,
  Session,
  SessionStatus,
  User,
} from "@/lib/types";

// ── small helpers ───────────────────────────────────────────────────
const AVATAR_PALETTE = ["#2563eb", "#7c3aed", "#0ea5e9", "#10b981", "#f59e0b", "#ef4444", "#ec4899", "#14b8a6"];
function avatarColor(seed: string): string {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
  return AVATAR_PALETTE[h % AVATAR_PALETTE.length];
}

// DB grade (user|media|moderator|admin|owner) → client Grade
export function mapGrade(g: string): Grade {
  switch (g) {
    case "owner":
      return "owner";
    case "admin":
    case "moderator":
      return "admin";
    case "media":
      return "reseller";
    default:
      return "user";
  }
}

// client Grade → DB grade (used when saving users)
export function unmapGrade(g: Grade): string {
  switch (g) {
    case "owner":
      return "owner";
    case "admin":
      return "admin";
    case "reseller":
      return "media";
    default:
      return "user";
  }
}

const STALE_AFTER_MS = 90_000; // heartbeat older than this → "stale"

// ── License ─────────────────────────────────────────────────────────
interface DbLicense {
  id: string;
  license_key: string;
  created_at: Date;
  expires_at: Date | null;
  status: string;
  user: { username: string } | null;
  product: { name: string; code: string } | null;
  _count?: { sessions: number };
}
export function mapLicense(l: DbLicense): License {
  return {
    id: l.id,
    key: l.license_key,
    username: l.user?.username ?? null,
    productCode: l.product?.code ?? "",
    productName: l.product?.name ?? "—",
    status: l.status as LicenseStatus,
    lifetime: l.expires_at === null,
    expiresAt: l.expires_at,
    sessions: l._count?.sessions ?? 0,
    // TODO: distinct HWID/IP counts require aggregating sessions per license;
    // defaulted to 0 so anti-share flagging stays inert until wired.
    distinctMachines: 0,
    distinctIps: 0,
    flagged: false,
    createdAt: l.created_at,
  };
}

// ── User ────────────────────────────────────────────────────────────
interface DbUser {
  id: string;
  username: string;
  discord_id: string | null;
  grade: string;
  created_at: Date;
  _count?: { licenses: number; machines: number };
}
// lastSeen is derived by the caller (max machine.last_seen_at for this user);
// falls back to the account creation date when the user has no machine.
export function mapUser(u: DbUser, lastSeen?: Date): User {
  return {
    id: u.id,
    username: u.username,
    discordId: u.discord_id ?? "",
    grade: mapGrade(u.grade),
    avatar: avatarColor(u.username),
    createdAt: u.created_at,
    lastSeen: lastSeen ?? u.created_at,
    licenseCount: u._count?.licenses ?? 0,
    machineCount: u._count?.machines ?? 0,
  };
}

// ── Machine ─────────────────────────────────────────────────────────
interface DbMachine {
  id: string;
  user_id: string;
  pc_name: string;
  hwid: string;
  os: string;
  gpu_name: string | null;
  cpu_brand: string | null;
  ram_hex: string | null;
  board_model: string | null;
  screen_info: string | null;
  storage_info: string | null;
  last_seen_at: Date;
  revoked_at: Date | null;
  user: { username: string } | null;
}
// licenseKey is resolved by the caller via machine.user_id → user → license.
export function mapMachine(m: DbMachine, licenseKey = ""): Machine {
  return {
    id: m.id,
    pcName: m.pc_name,
    username: m.user?.username ?? "",
    hwid: m.hwid,
    os: m.os,
    gpuName: m.gpu_name ?? undefined,
    cpuBrand: m.cpu_brand ?? undefined,
    ramHex: m.ram_hex ?? undefined,
    boardModel: m.board_model ?? undefined,
    screenInfo: m.screen_info ?? undefined,
    storageInfo: m.storage_info ?? undefined,
    status: m.revoked_at ? "banned" : "active",
    lastActivity: m.last_seen_at,
    licenseKey,
  };
}

// ── Session ─────────────────────────────────────────────────────────
interface DbSession {
  id: string;
  ip: string;
  started_at: Date;
  last_heartbeat_at: Date | null;
  ended_at: Date | null;
  license: {
    license_key: string;
    user: { username: string } | null;
    product: { name: string; code: string } | null;
  } | null;
  machine: { pc_name: string } | null;
}
export function mapSession(s: DbSession): Session {
  let status: SessionStatus;
  if (s.ended_at) status = "ended";
  else if (s.last_heartbeat_at && Date.now() - s.last_heartbeat_at.getTime() > STALE_AFTER_MS) status = "stale";
  else status = "active";
  return {
    id: s.id,
    username: s.license?.user?.username ?? "",
    licenseKey: s.license?.license_key ?? "",
    productCode: s.license?.product?.code ?? "",
    productName: s.license?.product?.name ?? "—",
    pcName: s.machine?.pc_name ?? "",
    ip: s.ip,
    startedAt: s.started_at,
    heartbeatAt: s.last_heartbeat_at ?? s.started_at,
    status,
  };
}

// ── Download ────────────────────────────────────────────────────────
interface DbDownload {
  id: string;
  download_id: string;
  downloaded_at: Date;
  ip_address: string | null;
  revoked: boolean;
  user: { username: string } | null;
  product: { name: string; code: string } | null;
}
export function mapDownload(d: DbDownload): Download {
  return {
    id: d.id,
    username: d.user?.username ?? "",
    productCode: d.product?.code ?? "",
    productName: d.product?.name ?? "—",
    date: d.downloaded_at,
    status: d.revoked ? "revoked" : "active",
    watermark: d.download_id,
    ip: d.ip_address ?? "",
  };
}

// ── Config ──────────────────────────────────────────────────────────
interface DbConfig {
  id: string;
  name: string;
  description: string | null;
  data: unknown;
  is_public: boolean;
  created_at: Date;
  user_configs?: { is_owner: boolean; user: { username: string } | null }[];
}
function parseModules(data: unknown): Record<string, ModuleSetting> {
  // The config payload is free-form JSON. The panel stores a flat map of
  // { moduleName: { enable, bind, mode, intensity, color } }. We also accept
  // the legacy { moduleName: true } / { moduleName: { enable: true } } shapes.
  const out: Record<string, ModuleSetting> = {};
  if (data && typeof data === "object" && !Array.isArray(data)) {
    for (const [k, v] of Object.entries(data as Record<string, unknown>)) {
      if (k === "version") continue;
      if (v === true) out[k] = { enable: true };
      else if (v && typeof v === "object") {
        const o = v as Record<string, unknown>;
        out[k] = {
          enable: o.enable === true,
          bind: typeof o.bind === "string" ? o.bind : undefined,
          mode: typeof o.mode === "string" ? o.mode : undefined,
          intensity: typeof o.intensity === "number" ? o.intensity : undefined,
          color: typeof o.color === "string" ? o.color : undefined,
        };
      }
    }
  }
  return out;
}
export function mapConfig(c: DbConfig): Config {
  const owner = c.user_configs?.find((uc) => uc.is_owner)?.user?.username ?? "Système";
  const version =
    c.data && typeof c.data === "object" && typeof (c.data as Record<string, unknown>).version === "string"
      ? ((c.data as Record<string, unknown>).version as string)
      : "v1.0";
  const modules = parseModules(c.data);
  return {
    id: c.id,
    name: c.name,
    owner,
    description: c.description ?? "",
    public: c.is_public,
    version,
    enabledCount: Object.values(modules).filter((m) => m.enable).length,
    createdAt: c.created_at,
    data: modules,
  };
}

// ── Blacklist ───────────────────────────────────────────────────────
interface DbBlacklist {
  id: string;
  reason: string | null;
  created_at: Date;
  expires_at: Date | null;
  created_by: string | null;
  user: { username: string } | null;
}
export function mapBlacklist(b: DbBlacklist): BlacklistEntry {
  return {
    id: b.id,
    username: b.user?.username ?? "",
    reason: b.reason ?? "",
    blacklistedAt: b.created_at,
    expiresAt: b.expires_at,
    by: b.created_by ?? "admin",
  };
}

// ── Product ─────────────────────────────────────────────────────────
interface DbProduct {
  id: string;
  code: string;
  name: string;
  description: string | null;
}
export function mapProduct(p: DbProduct): Product {
  return {
    id: p.id,
    code: p.code,
    name: p.name,
    description: p.description ?? "",
    icon: "package",
  };
}

// ── Audit ───────────────────────────────────────────────────────────
const AUDIT_CATS: AuditCategory[] = [
  "license",
  "security",
  "user",
  "machine",
  "session",
  "download",
  "product",
  "config",
  "auth",
  "server",
  "bot",
  "connection",
];
function mapAuditCategory(entity: string): AuditCategory {
  const e = entity.toLowerCase() as AuditCategory;
  return AUDIT_CATS.includes(e) ? e : "security";
}
// Build a natural-language sentence for the journal's "Action" column from the
// action code + the resolved actor + the raw detail (e.g. a license key). The
// raw detail also stays in AuditEntry.note for the drawer.
function describeAudit(action: string, actor: string, note?: string): string {
  const who = actor && actor !== "Système" ? actor : null;
  const admin = who ?? "Un admin";
  const obj = note ? ` ${note}` : "";
  switch (action) {
    // — Serveur / bot (système) —
    case "server.start": return "Le serveur a démarré";
    case "server.stop": return "Le serveur s'est arrêté";
    case "server.error": return "Erreur serveur";
    case "bot.start": return "Le bot a démarré";
    case "bot.stop": return "Le bot s'est arrêté";
    case "bot.error": return "Erreur du bot";
    // — Connexions client —
    case "client.connect": return who ? `${who} s'est connecté` : "Nouvelle connexion client";
    case "client.disconnect": return who ? `${who} s'est déconnecté` : "Déconnexion client";
    case "client.rejected": return "Connexion rejetée";
    // — Étapes d'authentification —
    case "auth.hello": return "Authentification — handshake";
    case "auth.init": return "Authentification — initialisation";
    case "auth.product_select": return "Authentification — sélection du produit";
    case "auth.client_auth": return "Authentification — requête client";
    case "auth.success": return who ? `${who} s'est authentifié` : "Authentification réussie";
    case "auth.failed": return who ? `Échec d'authentification de ${who}` : "Échec d'authentification";
    // — Auth panel —
    case "auth.login": return who ? `${who} s'est connecté au panel` : "Connexion au panel";
    case "auth.login_failed": return "Échec de connexion au panel";
    case "auth.login_denied": return "Accès au panel refusé";
    case "auth.logout": return who ? `${who} s'est déconnecté du panel` : "Déconnexion du panel";
    // — Downloads —
    case "download.request":
    case "download.keyed_request": return who ? `${who} a téléchargé un fichier` : "Téléchargement de fichier";
    case "download.generate": return who ? `${who} a généré un loader` : "Loader généré";
    // — Actions admin —
    case "license.revoke": return `${admin} a révoqué la licence${obj}`;
    case "license.restore": return `${admin} a réactivé la licence${obj}`;
    case "license.delete": return `${admin} a supprimé la licence${obj}`;
    case "license.suspend": return `${admin} a suspendu la licence${obj}`;
    case "license.extend": return `${admin} a prolongé la licence${obj}`;
    case "license.generate": return `${admin} a généré une licence`;
    case "user.create": return `${admin} a créé l'utilisateur${obj}`;
    case "user.edit": return `${admin} a modifié l'utilisateur${obj}`;
    case "user.delete": return `${admin} a supprimé l'utilisateur${obj}`;
    case "user.reset_password_request": return `${admin} a demandé une réinitialisation de mot de passe`;
    case "user.reset_password": return who ? `${who} a réinitialisé son mot de passe` : "Mot de passe réinitialisé";
    case "user.register": return who ? `${who} a créé son compte via Discord` : "Compte créé via Discord";
    case "user.blacklist": return `${admin} a blacklisté un utilisateur`;
    case "user.unblacklist": return `${admin} a levé un blacklist`;
    case "machine.ban": return `${admin} a banni la machine${obj}`;
    case "machine.unban": return `${admin} a réautorisé la machine${obj}`;
    case "machine.delete": return `${admin} a supprimé la machine${obj}`;
    case "machine.edit": return `${admin} a modifié la machine${obj}`;
    case "machine.reset_hwid": return `${admin} a réinitialisé le HWID${obj}`;
    case "session.kill": return `${admin} a terminé une session`;
    case "session.crash": return `${admin} a crashé une session (remote)`;
    case "download.revoke": return `${admin} a révoqué un téléchargement`;
    case "download.delete": return `${admin} a supprimé un téléchargement`;
    case "product.create": return `${admin} a créé le produit${obj}`;
    case "product.edit": return `${admin} a modifié le produit${obj}`;
    case "config.create": return `${admin} a créé la configuration${obj}`;
    case "config.edit": return `${admin} a modifié la configuration${obj}`;
    case "config.delete": return `${admin} a supprimé la configuration${obj}`;
    case "scan.run": return `${admin} a exécuté un scan leak`;
    case "rule.antishare": return `${admin} a appliqué une règle anti-partage`;
    default: return action;
  }
}
function deriveSeverity(action: string): AuditSeverity {
  const a = action.toLowerCase();
  if (/(delete|revoke|ban|blacklist|crash|kill)/.test(a)) return "danger";
  if (/(create|restore|generate|unban|unblacklist|register)/.test(a)) return "success";
  if (/(suspend|reset|extend)/.test(a)) return "caution";
  return "info";
}
interface DbAudit {
  id: string;
  action: string;
  entity: string;
  entity_id: string | null;
  details: string | null;
  created_at: Date;
  admin_id: string | null;
  admin: { username: string } | null;
}
export function mapAudit(
  a: DbAudit,
  userNames?: Map<string, string>,
  ips?: Map<string, string>,
): AuditEntry {
  const ip = ips?.get(a.id) ?? "";
  // server/bot lifecycle events are the only true "system" ones.
  const isLifecycle = a.entity === "server" || a.entity === "bot";
  let actor: string;
  if (a.admin?.username) actor = a.admin.username; // admin action
  else if (a.admin_id) actor = a.admin_id;
  else if (a.entity_id && userNames?.get(a.entity_id)) actor = userNames.get(a.entity_id)!; // user-attributed (auth/download)
  else if (isLifecycle) actor = "Système";
  else actor = ip || "Système"; // pre-auth connection/step with no user yet
  return {
    id: a.id,
    ts: a.created_at,
    actor,
    action: a.action,
    label: describeAudit(a.action, actor, a.details ?? undefined),
    note: a.details ?? undefined,
    cat: mapAuditCategory(a.entity),
    sev: isLifecycle && deriveSeverity(a.action) === "info" ? "neutral" : deriveSeverity(a.action),
    targetType: a.entity,
    target: a.entity_id ?? (isLifecycle ? "système" : "—"),
    ip,
  };
}
