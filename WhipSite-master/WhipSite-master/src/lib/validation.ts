// ════════════════════════════════════════════════════════════════════
//  WhipSite · zod validation schemas (forms + server actions)
// ════════════════════════════════════════════════════════════════════
import { z } from "zod";

export const loginSchema = z.object({
  username: z.string().min(1, "Identité requise."),
  password: z.string().min(1, "Clé secrète requise."),
});

export const userSchema = z.object({
  username: z.string().min(2, "2 caractères minimum."),
  password: z.string().min(6, "6 caractères minimum.").optional().or(z.literal("")),
  discordId: z.string().regex(/^\d*$/, "Identifiant Discord invalide.").optional().or(z.literal("")),
  grade: z.enum(["user", "reseller", "admin", "owner"]),
});

export const generateLicenseSchema = z.object({
  username: z.string().optional().or(z.literal("")),
  productCode: z.string().min(1),
  lifetime: z.boolean().default(false),
  expiresAt: z.coerce.date().optional().nullable(),
});

export const machineSchema = z.object({
  pcName: z.string().min(1),
  hwid: z.string().min(8),
  username: z.string().min(1),
  os: z.string().min(1),
});

export const blacklistSchema = z.object({
  username: z.string().min(1, "Utilisateur requis."),
  reason: z.string().optional().or(z.literal("")),
  expiresAt: z.coerce.date().optional().nullable(),
});

export const productSchema = z.object({
  name: z.string().min(1),
  code: z.string().min(1),
  description: z.string().optional().or(z.literal("")),
});

export const configSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional().or(z.literal("")),
  owner: z.string().optional().or(z.literal("")),
  public: z.boolean().default(false),
});

export const antiShareSchema = z.object({
  maxHwid: z.number().int().min(1).max(20),
  maxIp: z.number().int().min(1).max(40),
  autoSuspend: z.boolean(),
});

export type LoginInput = z.infer<typeof loginSchema>;
export type UserInput = z.infer<typeof userSchema>;
export type GenerateLicenseInput = z.infer<typeof generateLicenseSchema>;
export type MachineInput = z.infer<typeof machineSchema>;
export type BlacklistInput = z.infer<typeof blacklistSchema>;
export type ProductInput = z.infer<typeof productSchema>;
export type ConfigInput = z.infer<typeof configSchema>;
export type AntiShareInput = z.infer<typeof antiShareSchema>;
