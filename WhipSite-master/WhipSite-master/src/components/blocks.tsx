"use client";
// Shared page blocks: audit feed row, system status, live-session mini-row.
import {
  KeyRound,
  Shield,
  User as UserIcon,
  Monitor,
  Activity,
  Download,
  Package,
  FileCode,
  Lock,
  Server,
  Bot,
  Plug,
  RefreshCw,
  type LucideIcon,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { cn, timeAgo, fmtDuration } from "@/lib/utils";
import { Avatar } from "@/components/ui/primitives";
import { Ring } from "@/components/ui/charts";
import { getSystemMetrics } from "@/lib/server/actions/metrics";
import type { AuditEntry, AuditCategory, Session, VpsMetrics } from "@/lib/types";

export const AUDIT_CAT: Record<AuditCategory, { icon: LucideIcon; label: string }> = {
  license: { icon: KeyRound, label: "Licence" },
  security: { icon: Shield, label: "Sécurité" },
  user: { icon: UserIcon, label: "Utilisateur" },
  machine: { icon: Monitor, label: "Machine" },
  session: { icon: Activity, label: "Session" },
  download: { icon: Download, label: "Téléchargement" },
  product: { icon: Package, label: "Produit" },
  config: { icon: FileCode, label: "Config" },
  auth: { icon: Lock, label: "Auth" },
  server: { icon: Server, label: "Serveur" },
  bot: { icon: Bot, label: "Bot" },
  connection: { icon: Plug, label: "Connexion" },
};
export const SEV_COLOR: Record<string, string> = {
  success: "var(--whip-success)",
  danger: "var(--whip-danger)",
  info: "var(--whip-primary-bright)",
  caution: "var(--whip-caution)",
  warning: "var(--whip-warning)",
  neutral: "var(--whip-fg-subtle)",
};

export function AuditRow({ e, onClick, compact }: { e: AuditEntry; onClick?: () => void; compact?: boolean }) {
  const meta = AUDIT_CAT[e.cat] || AUDIT_CAT.auth;
  const Icon = meta.icon;
  return (
    <button
      className={cn("whip-auditrow", onClick && "whip-auditrow--click", compact && "whip-auditrow--compact")}
      onClick={onClick}
    >
      <span className="whip-auditrow__sev" style={{ background: SEV_COLOR[e.sev] }} />
      <span className="whip-auditrow__icon" style={{ color: SEV_COLOR[e.sev] }}>
        <Icon size={15} />
      </span>
      <span className="whip-auditrow__body">
        <span className="whip-auditrow__line">
          <strong>{e.actor}</strong> · {e.label}
        </span>
        <span className="whip-auditrow__sub">
          <span className="whip-mono">{e.target}</span>
          {!compact && (
            <>
              {" · "}
              <span className="whip-mono whip-mono--dim">{e.ip}</span>
            </>
          )}
        </span>
      </span>
      <span className="whip-auditrow__time">{timeAgo(e.ts)}</span>
    </button>
  );
}

const fmtBytes = (n: number) => {
  if (!n || n < 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
};
const fmtUptime = (s: number) => {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}j ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
};
// CPU/RAM/disk health thresholds → colour the gauge.
const usageTone = (p: number) => (p >= 90 ? "danger" : p >= 70 ? "warning" : "success");

/**
 * Live VPS resource usage (CPU / RAM / disk) of the box hosting the panel.
 * Polls the admin-only getSystemMetrics() action every 5s.
 */
export function SystemStatus() {
  const [m, setM] = useState<VpsMetrics | null>(null);
  const [err, setErr] = useState(false);
  const [loading, setLoading] = useState(false);
  // Guards stale async writes after unmount / between rapid refreshes.
  const aliveRef = useRef(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const d = await getSystemMetrics();
      if (!aliveRef.current) return;
      setM(d);
      setErr(false);
    } catch {
      if (aliveRef.current) setErr(true);
    } finally {
      if (aliveRef.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    aliveRef.current = true;
    refresh();
    const id = setInterval(refresh, 5000);
    return () => {
      aliveRef.current = false;
      clearInterval(id);
    };
  }, [refresh]);

  if (!m) return <div className="whip-vps__empty">{err ? "Métriques indisponibles." : "Chargement…"}</div>;

  const gauges = [
    { key: "CPU", pct: m.cpu.usage, sub: `${m.cpu.cores} cœurs · load ${m.cpu.load1}` },
    { key: "RAM", pct: m.mem.usage, sub: `${fmtBytes(m.mem.usedBytes)} / ${fmtBytes(m.mem.totalBytes)}` },
    ...(m.disk
      ? [{ key: "Disque", pct: m.disk.usage, sub: `${fmtBytes(m.disk.usedBytes)} / ${fmtBytes(m.disk.totalBytes)}` }]
      : []),
  ];

  return (
    <div className="whip-vps">
      <div className="whip-vps__gauges">
        {gauges.map((g) => (
          <div key={g.key} className="whip-vps__gauge">
            <Ring value={g.pct} total={100} size={86} stroke={8} color={`var(--whip-${usageTone(g.pct)})`}>
              <span className="whip-vps__pct">{g.pct}%</span>
            </Ring>
            <span className="whip-vps__name">{g.key}</span>
            <span className="whip-vps__sub whip-mono">{g.sub}</span>
          </div>
        ))}
      </div>
      <div className="whip-vps__foot whip-mono">
        <span>{m.hostname}</span>
        <span>uptime {fmtUptime(m.uptimeSec)}</span>
        <button
          type="button"
          className="whip-vps__refresh"
          onClick={refresh}
          disabled={loading}
          title="Actualiser les métriques"
        >
          <RefreshCw size={13} className={cn(loading && "whip-vps__spin")} />
          Actualiser
        </button>
      </div>
    </div>
  );
}

export function SessionMini({ s }: { s: Session }) {
  // Live session duration = now − startedAt, ticking every second. Starts
  // null (renders "—") until mounted to avoid a hydration mismatch.
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => {
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  const dur = now == null ? null : Math.max(0, now - new Date(s.startedAt).getTime());
  return (
    <div className="whip-sesmini">
      <span className="whip-sesmini__pulse" />
      <span className="whip-sesmini__meta">
        <span className="whip-sesmini__user">{s.username}</span>
        <span className="whip-sesmini__sub whip-mono">
          {s.pcName} · {s.ip}
        </span>
      </span>
      <span className="whip-sesmini__time" title="Durée de la session">{fmtDuration(dur)}</span>
    </div>
  );
}
