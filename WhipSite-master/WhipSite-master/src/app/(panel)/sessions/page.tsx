"use client";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Pause, Play, Activity, Ban, Trash2 as Trash, Monitor, Skull } from "lucide-react";
import { useApp } from "@/components/app-provider";
import { PageHeader, IconButton, StatusBadge } from "@/components/ui/primitives";
import { RefreshButton } from "@/components/ui/RefreshButton";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { cn, fmtDateTime, fmtDuration, timeAgo } from "@/lib/utils";
import type { Session } from "@/lib/types";

function SessionsInner() {
  const { data, actions, confirm } = useApp();
  const params = useSearchParams();
  const [paused, setPaused] = useState(false);
  const [activesOnly, setActivesOnly] = useState(false);
  // Real wall-clock "now", refreshed every second (0 until mounted to avoid
  // a hydration mismatch). NOT the mock NOW — sessions carry real timestamps.
  const [nowMs, setNowMs] = useState(0);

  useEffect(() => {
    setNowMs(Date.now());
    if (paused) return;
    const t = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(t);
  }, [paused]);

  const liveCount = data.sessions.filter((s) => s.status === "active").length;
  const rows = activesOnly ? data.sessions.filter((s) => s.status === "active") : data.sessions;

  const heartbeatColor = (s: Session) => {
    const base = nowMs || Date.now();
    const mins = (base - new Date(s.heartbeatAt).getTime()) / 60000;
    if (s.status === "active" && mins < 2) return "var(--whip-success)";
    if (mins < 10) return "var(--whip-warning)";
    return "var(--whip-danger)";
  };

  const columns: Column<Session>[] = [
    { key: "username", label: "User · Licence · Produit", render: (r) => <span className="whip-twoline"><span className="whip-twoline__a">{r.username}</span><span className="whip-twoline__b">{r.productName} · <span className="whip-mono">{r.licenseKey.slice(0, 14)}…</span></span></span> },
    { key: "pcName", label: "Machine · IP", width: 220, render: (r) => <span className="whip-twoline"><span className="whip-twoline__a" style={{ fontSize: 13 }}><Monitor size={13} style={{ marginRight: 6, color: "var(--whip-fg-subtle)", verticalAlign: -1 }} />{r.pcName}</span><span className="whip-twoline__b whip-mono">{r.ip}</span></span> },
    { key: "startedAt", label: "Démarrée", width: 150, sortable: true, sortValue: (r) => new Date(r.startedAt).getTime(), render: (r) => <span className="whip-mono whip-mono--dim" style={{ fontSize: 12 }}>{fmtDateTime(r.startedAt)}</span> },
    { key: "duration", label: "Durée", width: 120, sortable: true, sortValue: (r) => (r.status === "active" ? Date.now() : new Date(r.heartbeatAt).getTime()) - new Date(r.startedAt).getTime(), render: (r) => { const end = r.status === "active" ? nowMs : new Date(r.heartbeatAt).getTime(); const dur = nowMs === 0 && r.status === "active" ? null : end - new Date(r.startedAt).getTime(); return <span className={cn("whip-duration", r.status === "active" && "whip-duration--live")}><Activity size={12} />{fmtDuration(dur)}</span>; } },
    { key: "heartbeatAt", label: "Heartbeat", width: 110, render: (r) => <span className="whip-mono" style={{ fontSize: 12, color: heartbeatColor(r) }}>{timeAgo(r.heartbeatAt, new Date(nowMs || Date.now()))} ago</span> },
    { key: "status", label: "Statut", width: 110, render: (r) => (r.status === "active" ? <span className="abs-badge abs-badge--active"><span className="whip-livedot" />live</span> : <StatusBadge status={r.status} />) },
  ];
  const rowActions = (r: Session) =>
    r.status === "active" ? (
      <>
        <IconButton tone="danger" title="Terminer la session" icon={<Ban size={15} />} onClick={async () => { if (await confirm({ title: "Terminer la session ?", message: <>La session de <strong>{r.username}</strong> sur {r.pcName} sera coupée.</>, confirmLabel: "Terminer", tone: "danger" })) actions.killSession(r); }} />
        <IconButton tone="danger" title="Crash (remote)" icon={<Skull size={15} />} onClick={async () => { if (await confirm({ title: "Crasher la session ?", message: <>⚠️ Option nucléaire — le client de <strong>{r.username}</strong> sur {r.pcName} va volontairement planter (AV du process). À réserver aux cas extrêmes.</>, confirmLabel: "Crasher", tone: "danger" })) actions.crashSession(r); }} />
      </>
    ) : (
      <IconButton title="Supprimer" tone="danger" icon={<Trash size={15} />} onClick={() => actions.killSession(r)} disabled />
    );

  return (
    <>
      <PageHeader
        title="Sessions Live"
        eyebrow={`${liveCount} active${liveCount > 1 ? "s" : ""} · auto-refresh 5s`}
        actions={
          <>
            <RefreshButton />
            <button className="abs-btn abs-btn--secondary abs-btn--md" onClick={() => setPaused((p) => !p)}>{paused ? <Play size={15} /> : <Pause size={15} />}{paused ? "Reprendre" : "Pause"}</button>
            <button className={cn("abs-btn abs-btn--md", activesOnly ? "abs-btn--primary" : "abs-btn--secondary")} onClick={() => setActivesOnly((a) => !a)}><Activity size={15} />Actives seules</button>
          </>
        }
      />
      <DataTable
        columns={columns}
        rows={rows}
        rowKey="id"
        searchKeys={["username", "pcName", "ip", "licenseKey", "productName"]}
        searchPlaceholder="User · IP · PC · Licence · Produit…"
        initialSearch={params.get("focus") || ""}
        rowActions={rowActions}
        pageSize={12}
        defaultSort={{ key: "startedAt", dir: -1 }}
        emptyState={{ icon: <Activity size={24} />, title: "Aucune session", hint: activesOnly ? "Aucune session active actuellement." : "Aucune session enregistrée." }}
      />
    </>
  );
}

export default function SessionsPage() {
  return (
    <Suspense fallback={null}>
      <SessionsInner />
    </Suspense>
  );
}
