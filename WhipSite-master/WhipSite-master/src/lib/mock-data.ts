// ════════════════════════════════════════════════════════════════════
//  WhipSite · deterministic demo data (seeded PRNG)
//  Ported from the prototype so the rebuilt UI shows identical content.
//  In production replace this module with Prisma queries — the shapes
//  match src/lib/types.ts and prisma/schema.prisma.
// ════════════════════════════════════════════════════════════════════
import type {
  Product,
  User,
  License,
  Machine,
  Session,
  Download,
  Config,
  BlacklistEntry,
  AuditEntry,
  AuditCategory,
  AuditSeverity,
  Grade,
  LicenseStatus,
} from "./types";
import { NOW, DAY } from "./utils";

function mulberry32(a: number) {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rng = mulberry32(0x57484950); // "WHIP"
const rand = (n: number) => Math.floor(rng() * n);
const pick = <T,>(arr: T[]): T => arr[rand(arr.length)];
const chance = (p: number) => rng() < p;
const between = (a: number, b: number) => a + rand(b - a + 1);
const hex = (n: number) =>
  Array.from({ length: n }, () => "0123456789abcdef"[rand(16)]).join("");
const HEX = (n: number) =>
  Array.from({ length: n }, () => "0123456789ABCDEF"[rand(16)]).join("");
const dateAgo = (maxDays: number, minDays = 0) =>
  new Date(NOW.getTime() - (minDays + rng() * (maxDays - minDays)) * DAY);
const dateAhead = (maxDays: number, minDays = 0) =>
  new Date(NOW.getTime() + (minDays + rng() * (maxDays - minDays)) * DAY);

// ── Products ──
export const products: Product[] = [
  { id: "prd_client", code: "WHIP_CLIENT", name: "Whip Client", description: "The best minecraft client of the world", icon: "package" },
  { id: "prd_bypass", code: "WHIP_BYPASS", name: "Whip Bypass", description: "Bypass Method Of Whip Client", icon: "shield" },
];

// ── name generation ──
const seedNames = ["singerieGOAT", "singeriePORTABLE", "Xolep", "Vilflago", "Sankry", "Ivry", "St4yls", "t0ran", "blv", "6BO", "Kalers", "zervix", "zxom", "Stoned", "Takary", "Joblife"];
const pre = ["dark", "void", "neo", "zen", "kry", "flux", "nyx", "apex", "rax", "vex", "lum", "oni", "sky", "frost", "echo", "duno", "glitch", "razr", "syn", "kobe", "noct", "pyro", "aqua", "zer", "mort", "kael"];
const suf = ["ix", "oz", "ywn", "er", "ax", "us", "on", "ko", "ye", "qt", "fn", "zy", "0x", "pvp", "gg", "ttv", "lol", "69", "_yt", "op", "xd", "wtf", "mc"];
const usedNames = new Set<string>();
function genName() {
  let n = pick(pre) + pick(suf);
  if (chance(0.25)) n = n.charAt(0).toUpperCase() + n.slice(1);
  if (chance(0.15)) n += between(2, 99);
  return n;
}
function uniqueName(preferred?: string) {
  let n = preferred || genName();
  let guard = 0;
  while (usedNames.has(n.toLowerCase()) && guard++ < 50) n = genName();
  usedNames.add(n.toLowerCase());
  return n;
}
const discordId = () =>
  String(between(100000000, 999999999)) + String(between(100000000, 999999999)).slice(0, 9);
const avatarColors = ["#2563eb", "#7c3aed", "#0ea5e9", "#10b981", "#f59e0b", "#ef4444", "#ec4899", "#14b8a6", "#6366f1"];
const grades: Grade[] = ["user", "user", "user", "user", "user", "user", "user", "user", "admin", "reseller"];

// ── Users ──
export const users: User[] = [];
const TOTAL_USERS = 274;
for (let i = 0; i < TOTAL_USERS; i++) {
  const username = uniqueName(i < seedNames.length ? seedNames[i] : undefined);
  const grade: Grade = i === 0 ? "owner" : i < 4 ? "admin" : pick(grades);
  users.push({
    id: "usr_" + hex(8),
    username,
    discordId: discordId(),
    grade,
    createdAt: dateAgo(420, 1),
    avatar: pick(avatarColors),
    lastSeen: chance(0.7) ? dateAgo(14) : dateAgo(120, 14),
    licenseCount: 0,
    machineCount: 0,
  });
}
users[0].username = "mohtme";
usedNames.add("mohtme");
const userByName: Record<string, User> = Object.fromEntries(users.map((u) => [u.username, u]));
export const admins = users.filter((u) => u.grade === "owner" || u.grade === "admin").map((u) => u.username);

// ── Licenses ──
export const licenses: License[] = [];
const TOTAL_LIC = 348;
const licStatuses: LicenseStatus[] = ["active", "active", "active", "active", "active", "active", "expired", "revoked", "suspended"];
const licenseKey = () => "WHIP-" + HEX(4) + "-" + HEX(4) + "-" + HEX(4) + "-" + HEX(4);
for (let i = 0; i < TOTAL_LIC; i++) {
  const assigned = chance(0.88);
  const user = assigned ? pick(users) : null;
  const status = pick(licStatuses);
  const lifetime = chance(0.35);
  const product = chance(0.8) ? products[0] : products[1];
  const sessions = status === "active" ? between(0, 520) : between(0, 60);
  const distinctMachines = between(1, sessions > 100 ? 5 : 2);
  const distinctIps = distinctMachines + (chance(0.3) ? between(1, 4) : 0);
  licenses.push({
    id: "lic_" + hex(8),
    key: licenseKey(),
    username: user ? user.username : null,
    productCode: product.code,
    productName: product.name,
    status,
    lifetime,
    expiresAt: lifetime ? null : status === "expired" ? dateAgo(60, 1) : dateAhead(120, 2),
    sessions,
    createdAt: dateAgo(400, 0),
    distinctMachines,
    distinctIps,
    flagged: (distinctMachines >= 3 || distinctIps - distinctMachines >= 3) && status === "active",
  });
}
licenses.forEach((l) => {
  if (l.username && userByName[l.username]) userByName[l.username].licenseCount++;
});

// ── Machines ──
export const machines: Machine[] = [];
const TOTAL_MACHINES = 296;
const osList = ["Windows 10.0.26200", "Windows 10.0.26200", "Windows 10.0.19045", "Windows 10.0.22631", "Windows 11.0.26100"];
const pcWords = ["DESKTOP", "PC", "GAMING", "LAPTOP", "RIG", "HOME"];
for (let i = 0; i < TOTAL_MACHINES; i++) {
  const user = pick(users);
  user.machineCount++;
  const name = chance(0.7) ? "DESKTOP-" + HEX(6) : pick(pcWords) + (chance(0.5) ? "" : "-" + HEX(4));
  machines.push({
    id: "mac_" + hex(8),
    pcName: name,
    username: user.username,
    hwid: hex(48),
    os: pick(osList),
    lastActivity: chance(0.55) ? dateAgo(2) : dateAgo(70, 2),
    status: chance(0.92) ? "active" : "banned",
    licenseKey: pick(licenses).key,
  });
}

// ── Sessions ──
export const sessions: Session[] = [];
const TOTAL_SESSIONS = 640;
const activeLic = licenses.filter((l) => l.status === "active" && l.username);
for (let i = 0; i < TOTAL_SESSIONS; i++) {
  const lic = pick(activeLic);
  const mac = machines.find((m) => m.username === lic.username) || pick(machines);
  const started = dateAgo(7, 0);
  const active = i < 14;
  const heartbeat = active
    ? new Date(NOW.getTime() - rng() * 90 * 1000)
    : new Date(started.getTime() + rng() * 3 * 3600 * 1000);
  sessions.push({
    id: "ses_" + hex(8),
    username: lic.username!,
    licenseKey: lic.key,
    productCode: lic.productCode,
    productName: lic.productName,
    pcName: mac.pcName,
    ip: between(2, 254) + "." + between(1, 254) + "." + between(1, 254) + "." + between(1, 254),
    startedAt: started,
    heartbeatAt: heartbeat,
    status: active ? "active" : chance(0.05) ? "stale" : "ended",
  });
}
sessions.sort((a, b) => b.startedAt.getTime() - a.startedAt.getTime());

// ── Downloads ──
export const downloads: Download[] = [];
const TOTAL_DL = 812;
for (let i = 0; i < TOTAL_DL; i++) {
  const lic = pick(activeLic);
  downloads.push({
    id: HEX(32),
    username: lic.username!,
    productCode: lic.productCode,
    productName: lic.productName,
    date: dateAgo(120, 0),
    status: chance(0.88) ? "active" : "revoked",
    watermark: hex(16),
    ip: between(2, 254) + "." + between(1, 254) + "." + between(1, 254) + "." + between(1, 254),
  });
}
downloads.sort((a, b) => b.date.getTime() - a.date.getTime());

// ── Configs ──
export const combatModules = ["AimAssist", "AutoClicker", "AutoRefill", "Backtrack", "BlockHit", "KeepSprint", "Piercing", "Throw", "Velocity"];
export const visualModules = ["ArrayList", "Chams", "ESP", "NameTags", "TargetHUD", "Trajectories"];
const configSeed = ["pvprivals", "mmc blat très peu blat", "mmc test wih", "Planet PvP", "Planet PvP Totem", "PANDAK TOTEM", "PANDAK", "HERODIA", "HERODIA TOTEM", "Legit Settings v1", "Rage HvH", "Clean Reach", "Combo Bridge", "Sumo Only", "Crystal PvP", "NoFall Safe", "Bedwars Pro", "Skywars Rush"];
export const configs: Config[] = [];
const TOTAL_CONFIGS = 41;
for (let i = 0; i < TOTAL_CONFIGS; i++) {
  const ownerName = chance(0.45) ? "Système" : pick(users).username;
  configs.push({
    id: HEX(8) + "-" + HEX(4) + "-" + HEX(4) + "-" + HEX(4) + "-" + HEX(12),
    name: i < configSeed.length ? configSeed[i] : pick(["Rage", "Legit", "Clean", "Combo", "PvP", "HvH"]) + " " + pick(["Setup", "Cfg", "Preset", "Build"]) + " v" + between(1, 4),
    owner: ownerName,
    description: chance(0.3) ? pick(["Optimisé pour le ranked", "Settings tournoi", "Config publique communauté", "Test interne"]) : "",
    public: chance(0.22),
    createdAt: dateAgo(120, 1),
    version: "v2.0",
    enabledCount: between(3, 14),
  });
}

// ── Blacklist ──
const blReasons = ["Partage de licence", "Leak du client", "Chargeback Stripe", "Comportement toxique", "Tentative de crack", "Revente non autorisée", "Spoof HWID répété", "Fraude au remboursement"];
export const blacklist: BlacklistEntry[] = [];
for (let i = 0; i < 14; i++) {
  const u = pick(users);
  const perm = chance(0.5);
  blacklist.push({
    id: "bl_" + hex(8),
    username: u.username,
    reason: pick(blReasons),
    blacklistedAt: dateAgo(90, 0),
    expiresAt: perm ? null : dateAhead(60, 5),
    by: pick(admins),
  });
}
blacklist.sort((a, b) => b.blacklistedAt.getTime() - a.blacklistedAt.getTime());

// ── Audit log ──
const auditActions: { action: string; label: string; cat: AuditCategory; sev: AuditSeverity }[] = [
  { action: "license.revoke", label: "Licence révoquée", cat: "license", sev: "danger" },
  { action: "license.generate", label: "Licence générée", cat: "license", sev: "success" },
  { action: "license.extend", label: "Licence prolongée", cat: "license", sev: "info" },
  { action: "user.blacklist", label: "Utilisateur blacklisté", cat: "security", sev: "danger" },
  { action: "user.unblacklist", label: "Blacklist levée", cat: "security", sev: "success" },
  { action: "user.edit", label: "Utilisateur modifié", cat: "user", sev: "info" },
  { action: "user.create", label: "Utilisateur créé", cat: "user", sev: "success" },
  { action: "user.delete", label: "Utilisateur supprimé", cat: "user", sev: "danger" },
  { action: "machine.ban", label: "Machine bannie", cat: "machine", sev: "danger" },
  { action: "machine.reset_hwid", label: "HWID réinitialisé", cat: "machine", sev: "caution" },
  { action: "session.kill", label: "Session terminée", cat: "session", sev: "caution" },
  { action: "download.revoke", label: "Téléchargement révoqué", cat: "download", sev: "danger" },
  { action: "product.edit", label: "Produit modifié", cat: "product", sev: "info" },
  { action: "config.create", label: "Configuration créée", cat: "config", sev: "success" },
  { action: "config.edit", label: "Configuration modifiée", cat: "config", sev: "info" },
  { action: "scan.run", label: "Scan leak exécuté", cat: "security", sev: "info" },
  { action: "auth.login", label: "Connexion admin", cat: "auth", sev: "neutral" },
  { action: "auth.fail", label: "Échec de connexion", cat: "auth", sev: "caution" },
];
export const audit: AuditEntry[] = [];
for (let i = 0; i < 520; i++) {
  const a = pick(auditActions);
  let target = "";
  if (a.cat === "license" || a.cat === "download") target = pick(licenses).key;
  else if (a.cat === "machine" || a.cat === "session") target = pick(machines).pcName;
  else if (a.cat === "product") target = pick(products).name;
  else if (a.cat === "config") target = pick(configSeed);
  else target = pick(users).username;
  audit.push({
    id: "aud_" + hex(10),
    ts: dateAgo(45, 0),
    actor: pick(admins),
    action: a.action,
    label: a.label,
    cat: a.cat,
    sev: a.sev,
    targetType: a.cat,
    target,
    ip: between(2, 254) + "." + between(1, 254) + "." + between(1, 254) + "." + between(1, 254),
  });
}
audit.sort((a, b) => b.ts.getTime() - a.ts.getTime());

// ── Time series + KPIs ──
function series(days: number, base: number, variance: number, trend: number) {
  const out: number[] = [];
  let v = base;
  for (let i = 0; i < days; i++) {
    v = Math.max(0, v + (rng() - 0.5) * variance + trend);
    out.push(Math.round(v));
  }
  return out;
}
export const seriesData = {
  launches30: series(30, 95, 60, 1.6),
  newUsers30: series(30, 4, 4, 0.05),
  revenue30: series(30, 280, 180, 4),
  sessions30: series(30, 70, 40, 0.8),
};
const sum = (a: number[]) => a.reduce((x, y) => x + y, 0);

export const topUsers = [...users]
  .map((u) => ({
    ...u,
    launches: u.username === "singerieGOAT" ? 1653 : u.username === "Xolep" ? 474 : between(0, 230),
  }))
  .sort((a, b) => b.launches - a.launches)
  .slice(0, 12);

export const kpis = {
  users: users.length,
  products: products.length,
  activeLicenses: licenses.filter((l) => l.status === "active").length,
  liveSessions: sessions.filter((s) => s.status === "active").length,
  totalLaunches: 3494 + sum(seriesData.launches30),
  flaggedLicenses: licenses.filter((l) => l.flagged).length,
  bannedMachines: machines.filter((m) => m.status === "banned").length,
  revokedDownloads: downloads.filter((d) => d.status === "revoked").length,
  revenue30: sum(seriesData.revenue30),
};

export { userByName };
