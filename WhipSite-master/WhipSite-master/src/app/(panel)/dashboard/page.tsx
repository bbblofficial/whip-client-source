"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Users,
  KeyRound,
  Activity,
  Download as DownloadIcon,
  TrendingUp,
  LayoutGrid,
  ShieldAlert,
  Ban,
  UserX,
  Download,
  Clock,
  Check,
  ShieldCheck,
  ArrowRight,
  ChevronRight,
} from "lucide-react";
import { useApp } from "@/components/app-provider";
import { PageHeader, Segmented, EmptyState } from "@/components/ui/primitives";
import { StatCard } from "@/components/ui/StatCard";
import { Sparkline, BarMini, AreaChart, Donut } from "@/components/ui/charts";
import { StatusBadge } from "@/components/ui/primitives";
import { AuditRow, SystemStatus, SessionMini } from "@/components/blocks";
import { NOW, DAY, fmtNum, pct } from "@/lib/utils";
import { getPanelAnalytics } from "@/lib/server/panel-actions";
import type { PanelAnalytics } from "@/lib/types";

const sum = (a: number[]) => a.reduce((x, y) => x + y, 0);

// Anti-share / "partage suspecté" feature is parked for now. The logic stays
// in the codebase (isShared, applyAntiShare, flagged) — flip to true to bring
// the dashboard surfaces back.
const SHOW_ANTISHARE = false;

const STATUS_COLORS: Record<string, string> = {
  active: "var(--whip-success)",
  suspended: "var(--whip-warning)",
  revoked: "var(--whip-danger)",
  expired: "var(--whip-fg-subtle)",
};
const STATUS_FR: Record<string, string> = {
  active: "Actives",
  suspended: "Suspendues",
  revoked: "Révoquées",
  expired: "Expirées",
};

function KpiStrip({ a }: { a: PanelAnalytics | null }) {
  const { data } = useApp();
  const activeLic = data.licenses.filter((l) => l.status === "active").length;
  const liveSes = data.sessions.filter((s) => s.status === "active").length;
  const sessions = a?.sessions30 ?? [];
  const growth = a?.growth30 ?? [];
  return (
    <div className="whip-statgrid">
      <StatCard icon={<Users size={20} />} label="Utilisateurs" value={fmtNum(data.users.length)} spark={<Sparkline data={growth} />} tone="primary" />
      <StatCard icon={<KeyRound size={20} />} label="Licences actives" value={fmtNum(activeLic)} spark={<Sparkline data={sessions} />} tone="success" />
      <StatCard icon={<Activity size={20} />} label="Sessions live" value={fmtNum(liveSes)} live spark={<BarMini data={sessions.slice(-14)} />} tone="primary" />
      <StatCard icon={<DownloadIcon size={20} />} label="Téléchargements" value={fmtNum(data.downloads.length)} spark={<Sparkline data={sessions} color="var(--whip-success)" />} tone="success" />
    </div>
  );
}

function AlertStrip() {
  const { data } = useApp();
  const router = useRouter();
  const flagged = data.licenses.filter((l) => l.flagged).length;
  const blacklisted = data.blacklist.length;
  const banned = data.machines.filter((m) => m.status === "banned").length;
  const revoked = data.downloads.filter((d) => d.status === "revoked").length;
  const items = [
    // Parked: "Partage suspecté" card — see SHOW_ANTISHARE.
    ...(SHOW_ANTISHARE ? [{ icon: ShieldAlert, tone: "danger", label: "Partage suspecté", value: flagged, hint: "licences multi-HWID/IP", go: () => router.push("/licenses?preset=flagged") }] : []),
    { icon: UserX, tone: "danger", label: "Utilisateurs blacklistés", value: blacklisted, hint: "accès bannis", go: () => router.push("/blacklist") },
    { icon: Ban, tone: "warning", label: "Machines bannies", value: banned, hint: "accès bloqués", go: () => router.push("/machines") },
    { icon: Download, tone: "danger", label: "Downloads révoqués", value: revoked, hint: "liens invalidés", go: () => router.push("/downloads") },
  ];
  return (
    <div className="whip-alertstrip">
      {items.map((it) => (
        <button key={it.label} className="whip-alertcard" onClick={it.go}>
          <span className={`whip-alertcard__icon whip-stat__icon--${it.tone}`}>
            <it.icon size={17} />
          </span>
          <span className="whip-alertcard__meta">
            <span className="whip-alertcard__value">{fmtNum(it.value)}</span>
            <span className="whip-alertcard__label">{it.label}</span>
          </span>
          <span className="whip-alertcard__hint">
            {it.hint}
            <ChevronRight size={14} />
          </span>
        </button>
      ))}
    </div>
  );
}

function ExpiringList() {
  const { data } = useApp();
  const router = useRouter();
  const expiring = useMemo(
    () =>
      data.licenses
        .filter(
          (l) =>
            !l.lifetime &&
            l.expiresAt &&
            l.status === "active" &&
            new Date(l.expiresAt) > NOW &&
            new Date(l.expiresAt).getTime() - NOW.getTime() < 16 * DAY,
        )
        .sort((a, b) => new Date(a.expiresAt!).getTime() - new Date(b.expiresAt!).getTime())
        .slice(0, 6),
    [data.licenses],
  );
  return (
    <div className="whip-panel">
      <div className="whip-panel__head">
        <h3 className="whip-panel__title">Licences à renouveler</h3>
        <span className="whip-panel__hint">≤ 16 jours</span>
      </div>
      <div className="whip-panel__body" style={{ padding: 0 }}>
        {expiring.length === 0 ? (
          <EmptyState icon={<Check size={22} />} title="Rien à renouveler" hint="Aucune licence n'expire bientôt." />
        ) : (
          expiring.map((l) => {
            const days = Math.ceil((new Date(l.expiresAt!).getTime() - NOW.getTime()) / DAY);
            return (
              <div key={l.id} className="whip-exprow" onClick={() => router.push(`/licenses?focus=${l.id}`)}>
                <span className="whip-exprow__icon" style={{ color: days <= 5 ? "var(--whip-danger)" : "var(--whip-warning)" }}>
                  <Clock size={15} />
                </span>
                <span className="whip-exprow__meta">
                  <span className="whip-mono whip-exprow__key">{l.key}</span>
                  <span className="whip-exprow__user">
                    {l.username || "non assignée"} · {l.productName}
                  </span>
                </span>
                <span className={`abs-badge ${days <= 5 ? "abs-badge--revoked" : "abs-badge--expired"}`}>{days}j</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

function DashA({ a }: { a: PanelAnalytics | null }) {
  const { data } = useApp();
  const router = useRouter();
  const recent = data.audit.slice(0, 7);
  const live = data.sessions.filter((s) => s.status === "active").slice(0, 6);
  return (
    <>
      <KpiStrip a={a} />
      <AlertStrip />
      <div className="whip-grid whip-grid--7-5">
        <div className="whip-panel">
          <div className="whip-panel__head">
            <h3 className="whip-panel__title">Activité récente</h3>
            <button className="whip-link" onClick={() => router.push("/audit")}>
              Journal complet <ArrowRight size={13} />
            </button>
          </div>
          <div className="whip-panel__body" style={{ padding: 6 }}>
            {recent.length === 0 ? <EmptyState icon={<Activity size={22} />} title="Aucune activité" /> : recent.map((e) => (
              <AuditRow key={e.id} e={e} onClick={() => router.push("/audit")} />
            ))}
          </div>
        </div>
        <div className="whip-panel">
          <div className="whip-panel__head">
            <h3 className="whip-panel__title">Sessions live</h3>
            <button className="whip-link" onClick={() => router.push("/sessions")}>
              Tout voir <ArrowRight size={13} />
            </button>
          </div>
          <div className="whip-panel__body" style={{ padding: live.length ? 8 : 0 }}>
            {live.length === 0 ? (
              <EmptyState icon={<Activity size={22} />} title="Aucune session active" />
            ) : (
              live.map((s) => <SessionMini key={s.id} s={s} />)
            )}
          </div>
        </div>
      </div>
      <div className="whip-grid whip-grid--5-7">
        <ExpiringList />
        <div className="whip-panel">
          <div className="whip-panel__head">
            <h3 className="whip-panel__title">État du système</h3>
            <span className="abs-badge abs-badge--active">
              <span className="abs-badge__dot" />
              opérationnel
            </span>
          </div>
          <div className="whip-panel__body">
            <SystemStatus />
          </div>
        </div>
      </div>
    </>
  );
}

function DashB({ a }: { a: PanelAnalytics | null }) {
  const { data } = useApp();
  const router = useRouter();
  const series = a?.sessions30 ?? [];
  const labels = a?.labels ?? [];
  const clientLic = data.licenses.filter((l) => l.productCode === "WHIP_CLIENT").length;
  const bypassLic = data.licenses.filter((l) => l.productCode === "WHIP_BYPASS").length;
  const top = a?.topUsers.slice(0, 6) ?? [];
  const maxLaunch = Math.max(1, ...top.map((t) => t.sessions));
  const flagged = data.licenses.filter((l) => l.flagged).slice(0, 5);
  return (
    <>
      <KpiStrip a={a} />
      <div className="whip-panel">
        <div className="whip-panel__head">
          <h3 className="whip-panel__title">Lancements · 30 derniers jours</h3>
          <div className="whip-chartstats">
            <span>
              <strong>{fmtNum(sum(series))}</strong> total
            </span>
            <span>
              <strong>{series.length ? Math.round(sum(series) / 30) : 0}</strong> / jour
            </span>
            <span>
              <strong>{fmtNum(series.length ? Math.max(...series) : 0)}</strong> pic
            </span>
          </div>
        </div>
        <div className="whip-panel__body">
          <AreaChart data={series} labels={labels} h={230} />
        </div>
      </div>
      <div className="whip-grid whip-grid--3col">
        <div className="whip-panel">
          <div className="whip-panel__head">
            <h3 className="whip-panel__title">Répartition produits</h3>
          </div>
          <div className="whip-panel__body whip-donutbody">
            <Donut segments={[{ value: clientLic, color: "var(--whip-primary)" }, { value: bypassLic, color: "var(--whip-purple)" }]} />
            <div className="whip-legend">
              <div className="whip-legend__item">
                <span className="whip-legend__dot" style={{ background: "var(--whip-primary)" }} />
                Whip Client <strong>{fmtNum(clientLic)}</strong>
              </div>
              <div className="whip-legend__item">
                <span className="whip-legend__dot" style={{ background: "var(--whip-purple)" }} />
                Whip Bypass <strong>{fmtNum(bypassLic)}</strong>
              </div>
            </div>
          </div>
        </div>
        <div className="whip-panel">
          <div className="whip-panel__head">
            <h3 className="whip-panel__title">Top utilisateurs</h3>
            <span className="whip-panel__hint">sessions</span>
          </div>
          <div className="whip-panel__body" style={{ padding: 12 }}>
            {top.length === 0 ? <EmptyState icon={<Activity size={22} />} title="Aucune donnée" /> : top.map((u, i) => (
              <div key={u.username} className="whip-leadrow">
                <span className={`whip-leadrow__rank ${i === 0 ? "whip-leadrow__rank--gold" : ""}`}>{i + 1}</span>
                <span className="whip-leadrow__name">{u.username}</span>
                <span className="whip-leadrow__bar">
                  <span style={{ width: `${pct(u.sessions, maxLaunch)}%` }} />
                </span>
                <span className="whip-leadrow__val">{fmtNum(u.sessions)}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="whip-panel">
          <div className="whip-panel__head">
            <h3 className="whip-panel__title">Répartition statuts</h3>
            <span className="whip-panel__hint">licences</span>
          </div>
          <div className="whip-panel__body whip-donutbody">
            <Donut segments={(a?.licenseStatus ?? []).map((s) => ({ value: s.count, color: STATUS_COLORS[s.label] ?? "var(--whip-fg-subtle)" }))} />
            <div className="whip-legend">
              {(a?.licenseStatus ?? []).length === 0 ? (
                <span className="whip-muted">Aucune licence.</span>
              ) : (
                (a?.licenseStatus ?? []).map((s) => (
                  <div key={s.label} className="whip-legend__item">
                    <span className="whip-legend__dot" style={{ background: STATUS_COLORS[s.label] ?? "var(--whip-fg-subtle)" }} />
                    {STATUS_FR[s.label] ?? s.label} <strong>{fmtNum(s.count)}</strong>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
        {/* Parked: "Anti-partage" panel — see SHOW_ANTISHARE. */}
        {SHOW_ANTISHARE && (
          <div className="whip-panel">
            <div className="whip-panel__head">
              <h3 className="whip-panel__title">Anti-partage</h3>
              <span className="abs-badge abs-badge--revoked">{flagged.length} flags</span>
            </div>
            <div className="whip-panel__body" style={{ padding: flagged.length ? 8 : 0 }}>
              {flagged.length === 0 ? (
                <EmptyState icon={<ShieldCheck size={22} />} title="Aucun partage détecté" />
              ) : (
                flagged.map((l) => (
                  <div key={l.id} className="whip-exprow" onClick={() => router.push(`/licenses?focus=${l.id}`)}>
                    <span className="whip-exprow__icon" style={{ color: "var(--whip-danger)" }}>
                      <ShieldAlert size={15} />
                    </span>
                    <span className="whip-exprow__meta">
                      <span className="whip-mono whip-exprow__key">{l.key}</span>
                      <span className="whip-exprow__user">
                        {l.username} · {l.distinctMachines} machines · {l.distinctIps} IP
                      </span>
                    </span>
                    <ChevronRight size={15} style={{ color: "var(--whip-fg-subtle)" }} />
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </>
  );
}

export default function DashboardPage() {
  const { refreshing } = useApp();
  const [variant, setVariant] = useState<"A" | "B">("A");
  const [analytics, setAnalytics] = useState<PanelAnalytics | null>(null);
  useEffect(() => {
    const v = localStorage.getItem("whip.dashVariant");
    if (v === "A" || v === "B") setVariant(v);
  }, []);
  useEffect(() => {
    localStorage.setItem("whip.dashVariant", variant);
  }, [variant]);
  // Analytics charts: auto-refresh every 30s, and also re-pull whenever a
  // global panel refresh is triggered from the topbar button.
  const loadAnalytics = useCallback(() => {
    getPanelAnalytics().then(setAnalytics).catch(() => {});
  }, []);
  useEffect(() => {
    loadAnalytics();
    const id = setInterval(loadAnalytics, 30_000);
    return () => clearInterval(id);
  }, [loadAnalytics]);
  useEffect(() => {
    if (refreshing) loadAnalytics();
  }, [refreshing, loadAnalytics]);
  return (
    <>
      <PageHeader
        title="Dashboard"
        eyebrow="Surveillance système"
        actions={
          <Segmented
            value={variant}
            onChange={setVariant}
            options={[
              { value: "A", label: "Command center", icon: <LayoutGrid size={14} /> },
              { value: "B", label: "Analytics", icon: <TrendingUp size={14} /> },
            ]}
          />
        }
      />
      {variant === "A" ? <DashA a={analytics} /> : <DashB a={analytics} />}
    </>
  );
}
