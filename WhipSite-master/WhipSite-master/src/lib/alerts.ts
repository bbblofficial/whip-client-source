import type { License, AntiShareRules, Download } from "./types";
import { NOW, DAY } from "./utils";
import { isShared } from "@/components/app-provider";

export type AlertKind = "share" | "expire" | "billing" | "leak";
export interface AlertAction {
  label: string;
  type: string;
  tone?: "danger";
}
export interface Alert {
  id: string;
  sev: "danger" | "warning" | "info" | "neutral";
  icon: AlertKind;
  kind: AlertKind;
  ts: Date;
  title: string;
  desc: string;
  actions: AlertAction[];
  license?: License;
  username?: string;
  download?: Download;
}

const rank: Record<string, number> = { danger: 0, warning: 1, info: 2, neutral: 3 };

export function computeAlerts(
  data: { licenses: License[] },
  rules: AntiShareRules,
  dismissed: Set<string>,
  seeded: Alert[],
): Alert[] {
  const out: Alert[] = [];

  data.licenses
    .filter((l) => isShared(l, rules))
    .slice(0, 12)
    .forEach((l, i) => {
      out.push({
        id: "share_" + l.id,
        sev: "danger",
        icon: "share",
        kind: "share",
        license: l,
        ts: new Date(NOW.getTime() - i * 7 * 60000),
        title: "Partage suspecté",
        desc: `${l.key} · ${l.username || "non assignée"} — ${l.distinctMachines} HWID / ${l.distinctIps} IP`,
        actions: [
          { label: "Suspendre", type: "suspend", tone: "danger" },
          { label: "Voir", type: "view" },
        ],
      });
    });

  data.licenses
    .filter(
      (l) =>
        !l.lifetime &&
        l.expiresAt &&
        l.status === "active" &&
        new Date(l.expiresAt) > NOW &&
        new Date(l.expiresAt).getTime() - NOW.getTime() < 7 * DAY,
    )
    .sort((a, b) => new Date(a.expiresAt!).getTime() - new Date(b.expiresAt!).getTime())
    .slice(0, 8)
    .forEach((l, i) => {
      const days = Math.ceil((new Date(l.expiresAt!).getTime() - NOW.getTime()) / DAY);
      out.push({
        id: "exp_" + l.id,
        sev: "warning",
        icon: "expire",
        kind: "expire",
        license: l,
        ts: new Date(NOW.getTime() - i * 11 * 60000),
        title: `Licence expire dans ${days}j`,
        desc: `${l.key} · ${l.username || "non assignée"}`,
        actions: [
          { label: "Prolonger +30j", type: "extend" },
          { label: "Voir", type: "view" },
        ],
      });
    });

  seeded.forEach((a) => out.push(a));
  return out.filter((a) => !dismissed.has(a.id)).sort((a, b) => rank[a.sev] - rank[b.sev] || b.ts.getTime() - a.ts.getTime());
}

export const DEFAULT_RULES: AntiShareRules = { maxHwid: 2, maxIp: 4, autoSuspend: false };
