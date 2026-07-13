"use server";
// ════════════════════════════════════════════════════════════════════
//  WhipSite · panel server actions
//  The client AppProvider calls these. They run the real DB mutation
//  (reusing the existing lib/server/actions where possible), write an
//  audit-log row for traceability, and throw on failure so the client
//  can surface a danger toast. Args are the camelCase shapes the UI has.
// ════════════════════════════════════════════════════════════════════
import crypto from "crypto";
import prisma from "@/lib/server/prisma";
import { requireAdmin } from "@/lib/server/auth";
import { logAction } from "@/lib/server/logger";
import { notifySync } from "@/lib/server/sync";
import { unmapGrade } from "@/lib/server/mappers";
import type { Grade } from "@/lib/types";

import { updateLicenseStatus, deleteLicense, createLicense } from "@/lib/server/actions/licenses";
import { revokeMachine, unrevokeMachine, deleteMachine } from "@/lib/server/actions/machines";
import { closeSession, crashSession } from "@/lib/server/actions/sessions";
import { revokeDownload, unrevokeDownload, deleteDownload, createDownload } from "@/lib/server/actions/downloads";
import { blacklistUser, unblacklistUser } from "@/lib/server/actions/blacklist";
import { createUser, updateUser, deleteUser } from "@/lib/server/actions/users";
import { createProduct, updateProduct } from "@/lib/server/actions/products";
import { createConfig, updateConfig, deleteConfig } from "@/lib/server/actions/configs";
import { getAdvancedStats } from "@/lib/server/actions/stats";
import { getPanelData } from "@/lib/server/panel-data";
import type { PanelAnalytics } from "@/lib/types";

function fd(entries: Record<string, string | undefined | null>): FormData {
  const f = new FormData();
  for (const [k, v] of Object.entries(entries)) if (v != null) f.set(k, v);
  return f;
}

// ── Licenses ────────────────────────────────────────────────────────
export async function srvRevokeLicense(id: string, key: string) {
  const a = await requireAdmin();
  await updateLicenseStatus(id, "revoked");
  await logAction(a.userId, "license.revoke", "license", id, key);
}
export async function srvRestoreLicense(id: string, key: string) {
  const a = await requireAdmin();
  await updateLicenseStatus(id, "active");
  await logAction(a.userId, "license.restore", "license", id, key);
}
export async function srvSuspendLicense(id: string, key: string) {
  const a = await requireAdmin();
  await updateLicenseStatus(id, "suspended");
  await logAction(a.userId, "license.suspend", "license", id, key);
}
export async function srvDeleteLicense(id: string, key: string) {
  const a = await requireAdmin();
  await deleteLicense(id);
  await logAction(a.userId, "license.delete", "license", id, key);
}
export async function srvExtendLicense(id: string, key: string, days: number) {
  const a = await requireAdmin();
  await prisma.license.update({
    where: { id },
    data: { status: "active", expires_at: new Date(Date.now() + days * 86_400_000) },
  });
  await notifySync("license", "update", id);
  await logAction(a.userId, "license.extend", "license", id, `${key} +${days}j`);
}
export async function srvGenerateLicense(input: {
  username: string | null;
  productCode: string;
  lifetime: boolean;
  expiresAt: string | null;
}) {
  const a = await requireAdmin();
  const product = await prisma.product.findUnique({ where: { code: input.productCode } });
  if (!product) throw new Error(`Produit introuvable: ${input.productCode}`);
  await createLicense(
    fd({
      username: input.username ?? undefined,
      product_id: product.id,
      expires_at: input.lifetime ? undefined : input.expiresAt ?? undefined,
      lifetime: input.lifetime ? "on" : undefined,
    }),
  );
  await logAction(a.userId, "license.generate", "product", product.id, input.username ?? "—");
}

// ── Blacklist ───────────────────────────────────────────────────────
export async function srvBlacklistUser(input: { username: string; reason: string; expiresAt: string | null }) {
  const a = await requireAdmin();
  const user = await prisma.user.findUnique({ where: { username: input.username } });
  if (!user) throw new Error(`Utilisateur introuvable: ${input.username}`);
  await blacklistUser(user.id, input.reason, input.expiresAt, a.username);
  await logAction(a.userId, "user.blacklist", "user", user.id, input.reason);
}
export async function srvUnblacklist(id: string, username: string) {
  const a = await requireAdmin();
  await unblacklistUser(id);
  await logAction(a.userId, "user.unblacklist", "user", a.userId, username);
}

// ── Machines ────────────────────────────────────────────────────────
export async function srvBanMachine(id: string, pcName: string) {
  const a = await requireAdmin();
  await revokeMachine(id);
  await logAction(a.userId, "machine.ban", "machine", id, pcName);
}
export async function srvUnbanMachine(id: string, pcName: string) {
  const a = await requireAdmin();
  await unrevokeMachine(id);
  await logAction(a.userId, "machine.unban", "machine", id, pcName);
}
export async function srvDeleteMachine(id: string, pcName: string) {
  const a = await requireAdmin();
  await deleteMachine(id);
  await logAction(a.userId, "machine.delete", "machine", id, pcName);
}
// Reset HWID: drop the machine binding (sessions first to avoid FK), then
// NOTIFY the bot so it DMs the user to redownload the client.
export async function srvResetHwid(machineId: string, pcName: string) {
  const a = await requireAdmin();
  const machine = await prisma.machine.findUnique({ where: { id: machineId }, select: { user_id: true } });
  await prisma.$transaction(async (tx) => {
    await tx.session.deleteMany({ where: { machine_id: machineId } });
    await tx.machine.delete({ where: { id: machineId } });
  });
  await notifySync("machine", "delete", machineId);
  if (machine?.user_id) await prisma.$executeRaw`SELECT pg_notify('whip_hwid_reset', ${machine.user_id})`;
  await logAction(a.userId, "machine.reset_hwid", "machine", machineId, pcName);
}
export async function srvSaveMachine(id: string, data: { pcName?: string; os?: string; hwid?: string }) {
  const a = await requireAdmin();
  await prisma.machine.update({
    where: { id },
    data: { pc_name: data.pcName, os: data.os, hwid: data.hwid },
  });
  await notifySync("machine", "update", id);
  await logAction(a.userId, "machine.edit", "machine", id, data.pcName ?? "");
}

// ── Sessions ────────────────────────────────────────────────────────
export async function srvKillSession(id: string, pcName: string) {
  const a = await requireAdmin();
  await closeSession(id);
  await logAction(a.userId, "session.kill", "session", id, pcName);
}
export async function srvCrashSession(id: string, pcName: string) {
  const a = await requireAdmin();
  await crashSession(id);
  await logAction(a.userId, "session.crash", "session", id, pcName);
}

// ── Downloads ───────────────────────────────────────────────────────
export async function srvRevokeDownload(id: string, reason: string) {
  const a = await requireAdmin();
  await revokeDownload(id, reason);
  await logAction(a.userId, "download.revoke", "download", id, reason);
}
export async function srvUnrevokeDownload(id: string) {
  const a = await requireAdmin();
  await unrevokeDownload(id);
  await logAction(a.userId, "download.activate", "download", id);
}
export async function srvDeleteDownload(id: string) {
  const a = await requireAdmin();
  await deleteDownload(id);
  await logAction(a.userId, "download.delete", "download", id);
}
export async function srvRevokeAllDownloads(reason: string): Promise<number> {
  const a = await requireAdmin();
  const result = await prisma.download.updateMany({ where: { revoked: false }, data: { revoked: true, revoke_reason: reason } });
  await logAction(a.userId, "download.revoke_all", "download", null, `${result.count} revoked — ${reason}`);
  return result.count;
}
export async function srvCreateDownload(userId: string, productId: string | null): Promise<{ id: string; downloadId: string }> {
  const a = await requireAdmin();
  const result = await createDownload(userId, productId);
  await logAction(a.userId, "download.create", "download", result.id, `user:${userId}`);
  return result;
}

// ── Users ───────────────────────────────────────────────────────────
export async function srvSaveUser(
  input: { id?: string; username: string; discordId?: string; grade?: Grade; password?: string },
  isNew: boolean,
) {
  const a = await requireAdmin();
  const grade = input.grade ? unmapGrade(input.grade) : undefined;
  if (isNew) {
    // createUser requires a password (min 6). If the form didn't collect one,
    // mint a random placeholder so account creation still succeeds.
    const password = input.password && input.password.length >= 6 ? input.password : "Whip-" + crypto.randomUUID().slice(0, 10);
    await createUser(fd({ username: input.username, password, discord_id: input.discordId, grade }));
    await logAction(a.userId, "user.create", "user", a.userId, input.username);
  } else if (input.id) {
    await updateUser(input.id, fd({ username: input.username, password: input.password, discord_id: input.discordId, grade }));
    await logAction(a.userId, "user.edit", "user", input.id, input.username);
  }
}
// Fire a Postgres NOTIFY the bot listens on; it DMs the user a Discord button
// + modal to set a new password. No password handling happens here.
export async function srvResetPasswordRequest(userId: string, username: string) {
  const a = await requireAdmin();
  await prisma.$executeRaw`SELECT pg_notify('whip_password_reset', ${userId})`;
  await logAction(a.userId, "user.reset_password_request", "user", userId, username);
}
export async function srvDeleteUser(id: string, username: string) {
  const a = await requireAdmin();
  await deleteUser(id);
  await logAction(a.userId, "user.delete", "user", id, username);
}

// ── Products ────────────────────────────────────────────────────────
export async function srvSaveProduct(
  input: { id?: string; code: string; name: string; description?: string },
  isNew: boolean,
) {
  const a = await requireAdmin();
  if (isNew) {
    await createProduct(fd({ code: input.code, name: input.name, description: input.description }));
    await logAction(a.userId, "product.create", "product", a.userId, input.name);
  } else if (input.id) {
    await updateProduct(input.id, fd({ code: input.code, name: input.name, description: input.description }));
    await logAction(a.userId, "product.edit", "product", input.id, input.name);
  }
}

// ── Configs ─────────────────────────────────────────────────────────
export async function srvSaveConfig(
  input: { id?: string; name: string; description?: string; isPublic: boolean; data?: string },
  isNew: boolean,
) {
  const a = await requireAdmin();
  if (isNew) {
    await createConfig(
      fd({
        name: input.name,
        description: input.description,
        data: input.data ?? "{}",
        is_public: input.isPublic ? "on" : undefined,
        user_id: a.userId,
      }),
    );
    await logAction(a.userId, "config.create", "config", a.userId, input.name);
  } else if (input.id) {
    await updateConfig(
      input.id,
      fd({
        name: input.name,
        description: input.description,
        data: input.data,
        is_public: input.isPublic ? "on" : undefined,
      }),
    );
    await logAction(a.userId, "config.edit", "config", input.id, input.name);
  }
}
export async function srvDeleteConfig(id: string, name: string) {
  const a = await requireAdmin();
  await deleteConfig(id);
  await logAction(a.userId, "config.delete", "config", id, name);
}

// ── Security (audit-only for now) ───────────────────────────────────
export async function srvLogScan(label: string) {
  const a = await requireAdmin();
  await logAction(a.userId, "scan.run", "security", a.userId, label);
}
export async function srvLogAntiShare(label: string) {
  const a = await requireAdmin();
  await logAction(a.userId, "rule.antishare", "security", a.userId, label);
}

// Re-fetch the entire live dataset (every table the panel shows) so the
// client can refresh in place without a full page reload.
export async function refreshPanelData() {
  await requireAdmin();
  return getPanelData();
}

// ── Analytics (read) ────────────────────────────────────────────────
// Wraps getAdvancedStats and aligns the sparse per-day series onto a fixed
// 30-day window (0-filled) with ready-to-render labels.
export async function getPanelAnalytics(): Promise<PanelAnalytics> {
  const s = await getAdvancedStats();
  const now = new Date();
  const days: string[] = [];
  const labels: string[] = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 86_400_000);
    days.push(d.toISOString().split("T")[0]);
    labels.push(`${d.getDate()}/${d.getMonth() + 1}`);
  }
  const byDate = (arr: { date: string; count: number }[], key: string) => arr.find((x) => x.date === key)?.count ?? 0;
  return {
    labels,
    sessions30: days.map((d) => byDate(s.sessionsByDay, d)),
    growth30: days.map((d) => byDate(s.growth, d)),
    topUsers: s.topUsers,
    totalLaunches: s.totalLaunches,
    totalLaunches30d: s.totalLaunches30d,
    avgPerDay: s.avgLaunchesPerDay,
    licenseStatus: s.licenseStatus,
    osDistribution: s.osDistribution,
    products: s.products,
  };
}
