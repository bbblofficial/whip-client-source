// ════════════════════════════════════════════════════════════════════
//  WhipSite · domain types (mirror the Prisma models, client-safe)
// ════════════════════════════════════════════════════════════════════

export type Grade = "user" | "reseller" | "admin" | "owner";
export type LicenseStatus = "active" | "revoked" | "expired" | "suspended";
export type MachineStatus = "active" | "banned";
export type SessionStatus = "active" | "ended" | "stale";
export type DownloadStatus = "active" | "revoked";
export type AuditSeverity =
  | "success"
  | "danger"
  | "info"
  | "caution"
  | "warning"
  | "neutral";

export interface Product {
  id: string;
  code: string;
  name: string;
  description: string;
  icon: "package" | "shield";
}

export interface User {
  id: string;
  username: string;
  discordId: string;
  grade: Grade;
  avatar: string;
  createdAt: Date;
  lastSeen: Date;
  licenseCount: number;
  machineCount: number;
}

export interface License {
  id: string;
  key: string;
  username: string | null;
  productCode: string;
  productName: string;
  status: LicenseStatus;
  lifetime: boolean;
  expiresAt: Date | null;
  sessions: number;
  distinctMachines: number;
  distinctIps: number;
  flagged: boolean;
  createdAt: Date;
}

export interface Machine {
  id: string;
  pcName: string;
  username: string;
  hwid: string;
  os: string;
  gpuName?: string;
  cpuBrand?: string;
  ramHex?: string;
  boardModel?: string;
  screenInfo?: string;
  storageInfo?: string;
  status: MachineStatus;
  lastActivity: Date;
  licenseKey: string;
}

export interface MachineHistoryEntry {
  id: string;
  fieldName: string;
  oldValue: string | null;
  newValue: string | null;
  changedAt: Date;
}

export interface Session {
  id: string;
  username: string;
  licenseKey: string;
  productCode: string;
  productName: string;
  pcName: string;
  ip: string;
  startedAt: Date;
  heartbeatAt: Date;
  status: SessionStatus;
}

export interface Download {
  id: string;
  username: string;
  productCode: string;
  productName: string;
  date: Date;
  status: DownloadStatus;
  watermark: string;
  ip: string;
}

export interface Config {
  id: string;
  name: string;
  owner: string;
  description: string;
  public: boolean;
  version: string;
  enabledCount: number;
  createdAt: Date;
  /** Free-form module settings persisted in the DB `data` JSON column. */
  data?: Record<string, ModuleSetting>;
}

export interface ModuleSetting {
  enable: boolean;
  bind?: string;
  mode?: string;
  intensity?: number;
  color?: string;
}

export interface PanelAnalytics {
  labels: string[];
  sessions30: number[];
  growth30: number[];
  topUsers: { username: string; sessions: number }[];
  totalLaunches: number;
  totalLaunches30d: number;
  avgPerDay: string;
  licenseStatus: { label: string; count: number }[];
  osDistribution: { label: string; count: number }[];
  products: { name: string; active: number }[];
}

export interface BlacklistEntry {
  id: string;
  username: string;
  reason: string;
  blacklistedAt: Date;
  expiresAt: Date | null;
  by: string;
}

export interface AuditEntry {
  id: string;
  ts: Date;
  actor: string;
  action: string;
  label: string;
  /** Raw details string (shown only in the drawer, not the table). */
  note?: string;
  cat: AuditCategory;
  sev: AuditSeverity;
  targetType: string;
  target: string;
  ip: string;
}

export type AuditCategory =
  | "license"
  | "security"
  | "user"
  | "machine"
  | "session"
  | "download"
  | "product"
  | "config"
  | "auth"
  | "server"
  | "bot"
  | "connection";

export interface AntiShareRules {
  maxHwid: number;
  maxIp: number;
  autoSuspend: boolean;
}

/** Live resource usage of the VPS hosting the panel (CPU / RAM / disk). */
export interface VpsMetrics {
  cpu: { usage: number; cores: number; load1: number };
  mem: { usedBytes: number; totalBytes: number; usage: number };
  disk: { usedBytes: number; totalBytes: number; usage: number } | null;
  uptimeSec: number;
  hostname: string;
  capturedAt: string;
}
