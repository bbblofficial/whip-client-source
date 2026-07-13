"use client";
import { useEffect, useState } from "react";
import { Zap, Activity, Crown } from "lucide-react";
import { PageHeader } from "@/components/ui/primitives";
import { StatCard } from "@/components/ui/StatCard";
import { Sparkline, BarMini, AreaChart } from "@/components/ui/charts";
import { fmtNum, pct } from "@/lib/utils";
import { getPanelAnalytics } from "@/lib/server/panel-actions";
import type { PanelAnalytics } from "@/lib/types";

const sum = (a: number[]) => a.reduce((x, y) => x + y, 0);
const weekTrend = (s: number[]) => {
  const a = sum(s.slice(-7));
  const b = sum(s.slice(-14, -7)) || 1;
  return Math.round(((a - b) / b) * 100);
};

export default function StatsPage() {
  const [a, setA] = useState<PanelAnalytics | null>(null);
  const [err, setErr] = useState(false);
  useEffect(() => {
    getPanelAnalytics().then(setA).catch(() => setErr(true));
  }, []);

  if (err) {
    return (
      <>
        <PageHeader title="Analyses WHIP" eyebrow="Whip or get whipped" />
        <div className="whip-panel"><div className="whip-panel__body"><p className="whip-muted" style={{ padding: 24 }}>Impossible de charger les statistiques.</p></div></div>
      </>
    );
  }
  if (!a) {
    return (
      <>
        <PageHeader title="Analyses WHIP" eyebrow="Whip or get whipped" />
        <div className="whip-panel"><div className="whip-panel__body"><p className="whip-muted" style={{ padding: 24 }}>Chargement des statistiques…</p></div></div>
      </>
    );
  }

  const top = a.topUsers;
  const maxLaunch = Math.max(1, ...top.map((t) => t.sessions));
  return (
    <>
      <PageHeader title="Analyses WHIP" eyebrow="Whip or get whipped" />
      <div className="whip-statgrid whip-statgrid--3">
        <StatCard icon={<Zap size={20} />} label="Total lancements" value={fmtNum(a.totalLaunches)} trend={weekTrend(a.sessions30)} spark={<Sparkline data={a.sessions30} w={150} />} tone="primary" />
        <StatCard icon={<Activity size={20} />} label="Moyenne / jour" value={a.avgPerDay} spark={<BarMini data={a.sessions30.slice(-14)} w={150} />} tone="success" />
        <StatCard icon={<Crown size={20} />} label="Top utilisateur" value={top[0]?.username ?? "—"} tone="purple" />
      </div>
      <div className="whip-panel">
        <div className="whip-panel__head">
          <h3 className="whip-panel__title">Flux de lancements</h3>
          <span className="whip-panel__hint">30 derniers jours</span>
        </div>
        <div className="whip-panel__body">
          <AreaChart data={a.sessions30} labels={a.labels} h={260} />
        </div>
      </div>
      <div className="whip-grid whip-grid--7-5">
        <div className="whip-panel">
          <div className="whip-panel__head">
            <h3 className="whip-panel__title">Utilisateurs d&apos;élite</h3>
            <span className="whip-panel__hint">par sessions</span>
          </div>
          <div className="whip-panel__body" style={{ padding: 12 }}>
            {top.length === 0 ? (
              <p className="whip-muted" style={{ padding: 12 }}>Aucune session enregistrée.</p>
            ) : (
              top.slice(0, 10).map((u, i) => (
                <div key={u.username} className="whip-leadrow">
                  <span className={`whip-leadrow__rank ${i === 0 ? "whip-leadrow__rank--gold" : ""}`}>{i + 1}</span>
                  <span className="whip-leadrow__name">{u.username}</span>
                  <span className="whip-leadrow__bar"><span style={{ width: `${pct(u.sessions, maxLaunch)}%` }} /></span>
                  <span className="whip-leadrow__val">{fmtNum(u.sessions)} <small>sess.</small></span>
                </div>
              ))
            )}
          </div>
        </div>
        <div className="whip-panel">
          <div className="whip-panel__head">
            <h3 className="whip-panel__title">Licences créées</h3>
            <span className="whip-panel__hint">30j</span>
          </div>
          <div className="whip-panel__body">
            <AreaChart data={a.growth30} labels={a.labels} h={150} color="var(--whip-purple)" />
            <div className="whip-statline">
              <div><span className="whip-statline__n">{fmtNum(sum(a.growth30))}</span><span className="whip-statline__l">licences créées (30j)</span></div>
              <div><span className="whip-statline__n">{fmtNum(a.totalLaunches30d)}</span><span className="whip-statline__l">lancements (30j)</span></div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
