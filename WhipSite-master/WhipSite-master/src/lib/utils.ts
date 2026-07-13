// ════════════════════════════════════════════════════════════════════
//  WhipSite · shared utilities
// ════════════════════════════════════════════════════════════════════
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import {
  format,
  formatDistanceStrict,
  differenceInSeconds,
} from "date-fns";
import { fr } from "date-fns/locale";

/** Tailwind-aware className combiner (clsx + tailwind-merge). */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Reference "now" — swap for `new Date()` once wired to live data. */
export const NOW = new Date("2026-06-13T22:15:00");
export const DAY = 86_400_000;

export function fmtDate(d: Date | string | null | undefined) {
  if (!d) return "—";
  return format(new Date(d), "dd/MM/yyyy");
}

export function fmtDateTime(d: Date | string | null | undefined) {
  if (!d) return "—";
  return format(new Date(d), "dd/MM/yyyy HH:mm:ss");
}

// Live data carries real timestamps, so "X ago" must be measured against the
// real wall-clock now — NOT the fixed mock NOW (which sits in the past and
// would clamp every recent timestamp to "0s"). Evaluated per call.
export function timeAgo(d: Date | string | null | undefined, base: Date = new Date()) {
  if (!d) return "—";
  const s = Math.max(0, differenceInSeconds(base, new Date(d)));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  const days = Math.floor(h / 24);
  if (days < 30) return `${days}j`;
  return `${Math.floor(days / 30)}mois`;
}

/** Human duration: 45s · 12min · 2h 30min · 1j 4h */
export function fmtDuration(ms: number | null | undefined) {
  if (ms == null || ms < 0) return "—";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}min`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  if (h < 24) return rm ? `${h}h ${rm}min` : `${h}h`;
  const d = Math.floor(h / 24);
  const rh = h % 24;
  return rh ? `${d}j ${rh}h` : `${d}j`;
}

export function fmtNum(n: number) {
  return Number(n).toLocaleString("fr-FR");
}

export function fmtMoney(n: number) {
  return `${Number(n).toLocaleString("fr-FR")} €`;
}

export function shortHwid(h: string | null | undefined) {
  return h ? `${h.slice(0, 10)}…` : "—";
}

export function pct(part: number, total: number) {
  return total ? Math.round((part / total) * 100) : 0;
}

export { fr, formatDistanceStrict };
